package com.shilapi.xcertplay.usbbt

import android.util.Log
import com.shilapi.xcertplay.usbbt.HciProtocol.EVT_IO_CAPABILITY_REQUEST
import com.shilapi.xcertplay.usbbt.HciProtocol.EVT_LINK_KEY_NOTIFICATION
import com.shilapi.xcertplay.usbbt.HciProtocol.EVT_SIMPLE_PAIRING_COMPLETE
import com.shilapi.xcertplay.usbbt.HciProtocol.EVT_USER_CONFIRMATION_REQUEST
import com.shilapi.xcertplay.usbbt.HciProtocol.IO_CAP_NO_INPUT_NO_OUTPUT
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_IO_CAPABILITY_REQUEST_REPLY
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_USER_CONFIRMATION_REQUEST_REPLY
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Secure Simple Pairing agent for the USB Bluetooth dongle (Phase 4).
 *
 * Runs a background event pump on [hci] that handles the pairing handshake
 * with "Just Works" semantics (no display, no input — appropriate for a
 * head unit with no trusted UI during drive):
 * - IO_Capability_Request (0x31) -> reply NoInputNoOutput
 * - User_Confirmation_Request (0x33) -> auto-confirm
 * - Link_Key_Notification (0x18) -> persist via [LinkKeyStore]
 * - Simple_Pairing_Complete (0x36) -> log outcome
 *
 * Pairing is triggered by the peer (iPhone) connecting; this agent only
 * answers. Start via [start], stop via [stop]. Thread-safe.
 *
 * Clean-room: SSP flow per Bluetooth Core Spec Vol 2, Part E.
 */
class UsbBtPairingAgent(
    private val hci: UsbBtHci,
    private val linkKeys: LinkKeyStore,
) {

    companion object {
        private const val TAG = "UsbBtPairingAgent"
    }

    private val running = AtomicBoolean(false)
    private var pumpThread: Thread? = null

    /** Start the event pump. Idempotent. */
    fun start() {
        if (!running.compareAndSet(false, true)) return
        pumpThread = Thread(::pumpLoop, "UsbBtPairing").apply {
            isDaemon = true
            start()
        }
        Log.i(TAG, "pairing agent started")
    }

    fun stop() {
        running.set(false)
        pumpThread?.interrupt()
        pumpThread = null
        Log.i(TAG, "pairing agent stopped")
    }

    private fun pumpLoop() {
        while (running.get()) {
            val event = try {
                hci.pollEvent(timeoutMs = 500)
            } catch (t: Throwable) {
                if (running.get()) Log.w(TAG, "event poll failed", t)
                null
            } ?: continue
            runCatching { handleEvent(event) }
                .onFailure { Log.w(TAG, "pairing event handler failed", it) }
        }
    }

    private fun handleEvent(event: HciProtocol.HciEvent) {
        when (event.code) {
            EVT_IO_CAPABILITY_REQUEST -> onIoCapabilityRequest(event)
            EVT_USER_CONFIRMATION_REQUEST -> onUserConfirmationRequest(event)
            EVT_LINK_KEY_NOTIFICATION -> onLinkKeyNotification(event)
            EVT_SIMPLE_PAIRING_COMPLETE -> onSimplePairingComplete(event)
            else -> { /* not pairing-related; ignore */ }
        }
    }

    private fun bdAddrFrom(event: HciProtocol.HciEvent): String? {
        if (event.params.size < 6) return null
        return (5 downTo 0).joinToString(":") { i ->
            "%02X".format(event.params[i])
        }
    }

    /**
     * IO_Capability_Request: params = BD_ADDR(6). Reply with our
     * NoInputNoOutput capability -> Just Works pairing.
     */
    private fun onIoCapabilityRequest(event: HciProtocol.HciEvent) {
        val bdAddr = bdAddrFrom(event) ?: return
        // Reply params: BD_ADDR(6) | io_capability(1) | oob_data(1)=0 | auth_req(1)
        // auth_req: bit0 = MITM not required, bit2 = general bonding.
        val reply = event.params.copyOfRange(0, 6) +
            byteArrayOf(IO_CAP_NO_INPUT_NO_OUTPUT.toByte(), 0x00, 0x04)
        when (val r = hci.sendCommand(OP_IO_CAPABILITY_REQUEST_REPLY, reply)) {
            is UsbBtHci.HciResult.Ok ->
                Log.i(TAG, "IO capability replied (NoInNoOut) for $bdAddr")
            is UsbBtHci.HciResult.Failed ->
                Log.w(TAG, "IO capability reply failed for $bdAddr: ${r.reason}")
        }
    }

    /**
     * User_Confirmation_Request: params = BD_ADDR(6) | numeric_value(4).
     * Just Works: auto-confirm without showing the value.
     */
    private fun onUserConfirmationRequest(event: HciProtocol.HciEvent) {
        val bdAddr = bdAddrFrom(event) ?: return
        // Reply params: BD_ADDR(6).
        val reply = event.params.copyOfRange(0, 6)
        when (val r = hci.sendCommand(OP_USER_CONFIRMATION_REQUEST_REPLY, reply)) {
            is UsbBtHci.HciResult.Ok ->
                Log.i(TAG, "auto-confirmed pairing for $bdAddr (Just Works)")
            is UsbBtHci.HciResult.Failed ->
                Log.w(TAG, "auto-confirm failed for $bdAddr: ${r.reason}")
        }
    }

    /**
     * Link_Key_Notification: params = BD_ADDR(6) | link_key(16) | key_type(1).
     * Persist the key so future connections can skip pairing.
     */
    private fun onLinkKeyNotification(event: HciProtocol.HciEvent) {
        if (event.params.size < 23) {
            Log.w(TAG, "malformed Link_Key_Notification (${event.params.size} bytes)")
            return
        }
        val bdAddr = bdAddrFrom(event) ?: return
        val key = event.params.copyOfRange(6, 22)
        linkKeys.store(bdAddr, key)
    }

    private fun onSimplePairingComplete(event: HciProtocol.HciEvent) {
        if (event.params.size < 8) return
        val status = event.params[0].toInt() and 0xFF
        val bdAddr = bdAddrFrom(event) ?: "?"
        Log.i(
            TAG,
            if (status == 0) "pairing complete with $bdAddr"
            else "pairing FAILED with $bdAddr status=0x${status.toString(16)}",
        )
    }
}
