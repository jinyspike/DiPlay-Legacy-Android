package com.shilapi.xcertplay.usbbt

import android.util.Log
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_PSM_RFCOMM
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_DLCI_CONTROL
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_DM
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_MCC
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_MCC_MSC
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_MCC_PN
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_SABM
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_UA
import com.shilapi.xcertplay.usbbt.HciProtocol.RFCOMM_UIH
import com.shilapi.xcertplay.usbbt.HciProtocol.rfcommDlci
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * RFCOMM layer over L2CAP (Phase 3).
 *
 * Bluetooth Core Spec, RFCOMM with TS 07.10. Implements the subset needed for
 * iAP2:
 * - session establishment on DLCI 0 (SABM/UA)
 * - DLC establishment to a server channel: PN negotiation -> SABM/UA -> MSC
 * - UIH data frames with single-byte length (payloads < 128 bytes per frame;
 *   larger writes are fragmented)
 * - inbound UIH dispatch to per-DLC handlers; inbound SABM on a DLC is
 *   answered with UA (we only initiate as a client, but tolerate it)
 *
 * All public methods block the calling thread; use from a background thread.
 * One instance per L2CAP RFCOMM channel.
 *
 * Clean-room: derived from the public Bluetooth Core Specification.
 */
class RfcommLayer(
    private val l2cap: L2capLayer,
    private val channel: L2capLayer.Channel,
) {

    /** An open RFCOMM data link connection to a server channel. */
    data class Dlc(val serverChannel: Int, val dlci: Int)

    sealed class RfcommResult<out T> {
        data class Ok<T>(val value: T) : RfcommResult<T>()
        data class Failed(val reason: String) : RfcommResult<Nothing>()
    }

    companion object {
        private const val TAG = "RfcommLayer"
        private const val HANDSHAKE_TIMEOUT_MS = 5_000L
        private const val MAX_UIH_PAYLOAD = 100 // keep frames small for old dongles
    }

    /** dlci -> pending UA latch (for SABM we sent). */
    private val pendingUa = ConcurrentHashMap<Int, CountDownLatch>()

    /** dlci -> pending PN response latch. */
    private val pendingPn = ConcurrentHashMap<Int, CountDownLatch>()

    /** dlci -> data handler. */
    private val dataHandlers = ConcurrentHashMap<Int, (ByteArray) -> Unit>()

    @Volatile private var sessionOpen = false
    @Volatile private var closed = false

    init {
        l2cap.onData(channel) { payload -> onRfcommFrame(payload) }
    }

    // ------------------------------------------------------------------
    // Frame encoding.
    // ------------------------------------------------------------------

    /** Address field: EA=1, C/R bit, DLCI (6 bits). We are the initiator (C/R=1 on commands). */
    private fun addressField(dlci: Int, command: Boolean): Byte =
        (0x01 or (if (command) 0x02 else 0x00) or (dlci shl 2)).toByte()

    /** Length field with EA=1 (single byte, max 127). */
    private fun lengthField(len: Int): ByteArray {
        require(len in 0..127) { "length $len exceeds single-byte field" }
        return byteArrayOf(((len shl 1) or 0x01).toByte())
    }

    /** FCS over address+control+length(+data) using the CRC-8 from TS 07.10. */
    private fun fcs(bytes: ByteArray): Byte {
        var crc = 0xFF
        for (b in bytes) {
            crc = crc xor (b.toInt() and 0xFF)
            repeat(8) {
                crc = if (crc and 0x01 != 0) (crc ushr 1) xor 0xE0 else crc ushr 1
            }
        }
        return (0xFF - crc).toByte()
    }

    /** Build a complete RFCOMM frame: address | control | length | [data] | fcs. */
    private fun buildFrame(dlci: Int, control: Int, data: ByteArray = byteArrayOf()): ByteArray {
        val addr = addressField(dlci, command = true)
        val ctrl = (control and 0xFF).toByte()
        val len = lengthField(data.size)
        val header = byteArrayOf(addr, ctrl) + len
        val frame = header + data
        return frame + fcs(frame)
    }

    private fun sendFrame(dlci: Int, control: Int, data: ByteArray = byteArrayOf()): Boolean {
        if (closed) return false
        return l2cap.send(channel, buildFrame(dlci, control, data))
    }

    // ------------------------------------------------------------------
    // Session and DLC establishment.
    // ------------------------------------------------------------------

    /**
     * Open the RFCOMM session (SABM/UA on DLCI 0). Idempotent.
     */
    fun openSession(): RfcommResult<Unit> {
        if (sessionOpen) return RfcommResult.Ok(Unit)
        if (closed) return RfcommResult.Failed("RFCOMM closed")
        val latch = CountDownLatch(1)
        pendingUa[RFCOMM_DLCI_CONTROL] = latch
        try {
            if (!sendFrame(RFCOMM_DLCI_CONTROL, RFCOMM_SABM)) {
                return RfcommResult.Failed("failed to send SABM (session)")
            }
            if (!latch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                return RfcommResult.Failed("SABM/UA timeout (session)")
            }
            sessionOpen = true
            Log.i(TAG, "RFCOMM session open")
            return RfcommResult.Ok(Unit)
        } finally {
            pendingUa.remove(RFCOMM_DLCI_CONTROL)
        }
    }

    /**
     * Open a DLC to [serverChannel]: PN negotiation, SABM/UA, then MSC.
     * Returns the DLC on success.
     */
    fun openDlc(serverChannel: Int): RfcommResult<Dlc> {
        val session = openSession()
        if (session is RfcommResult.Failed) return session
        val dlci = rfcommDlci(serverChannel, initiator = true)

        // 1) Parameter Negotiation (MCC PN).
        val pnLatch = CountDownLatch(1)
        pendingPn[dlci] = pnLatch
        try {
            // PN request: MCC type 0x20, length 8: dlci | frame_type=UIH | priority
            // | ack_timer | max_frame_size(2 LE) | max_retrans | credits
            val pnReq = mccFrame(
                RFCOMM_MCC_PN,
                byteArrayOf(
                    dlci.toByte(), RFCOMM_UIH.toByte(), 0x00, 0x00,
                    0xF8.toByte(), 0x01, // max frame 504
                    0x00, 0x07, // no retransmissions, 7 initial credits
                ),
            )
            if (!sendFrame(RFCOMM_DLCI_CONTROL, RFCOMM_UIH, pnReq)) {
                return RfcommResult.Failed("failed to send PN (ch=$serverChannel)")
            }
            if (!pnLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                Log.w(TAG, "PN timeout (ch=$serverChannel); continuing without negotiation")
            }
        } finally {
            pendingPn.remove(dlci)
        }

        // 2) SABM/UA on the DLC.
        val uaLatch = CountDownLatch(1)
        pendingUa[dlci] = uaLatch
        try {
            if (!sendFrame(dlci, RFCOMM_SABM)) {
                return RfcommResult.Failed("failed to send SABM (ch=$serverChannel)")
            }
            if (!uaLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                return RfcommResult.Failed("SABM/UA timeout (ch=$serverChannel)")
            }
        } finally {
            pendingUa.remove(dlci)
        }

        // 3) Modem Status Command (MSC): signal DTR/RTC ready.
        val msc = mccFrame(
            RFCOMM_MCC_MSC,
            byteArrayOf(
                // MSC: dlci | V.24 signals (EA=1, RTC=1, RTR=1, DV=1)
                ((dlci shl 2) or 0x01).toByte(),
                0x8D.toByte(),
            ),
        )
        sendFrame(RFCOMM_DLCI_CONTROL, RFCOMM_UIH, msc)

        Log.i(TAG, "RFCOMM DLC open: ch=$serverChannel dlci=$dlci")
        return RfcommResult.Ok(Dlc(serverChannel = serverChannel, dlci = dlci))
    }

    /**
     * Wrap an MCC payload: type(1) | length(1, EA=1) | value.
     * The C/R bit of the type byte is set for commands.
     */
    private fun mccFrame(type: Int, value: ByteArray): ByteArray {
        val header = byteArrayOf(
            ((type and 0xFF) or 0x01).toByte(), // C/R = command
            (((value.size shl 1) or 0x01) and 0xFF).toByte(),
        )
        return header + value
    }

    /** Send [data] on [dlc], fragmenting into small UIH frames. */
    fun send(dlc: Dlc, data: ByteArray): Boolean {
        if (closed) return false
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + MAX_UIH_PAYLOAD, data.size)
            if (!sendFrame(dlc.dlci, RFCOMM_UIH, data.copyOfRange(offset, end))) return false
            offset = end
        }
        return true
    }

    /** Register a handler for inbound data on [dlc]. */
    fun onData(dlc: Dlc, handler: (ByteArray) -> Unit) {
        dataHandlers[dlc.dlci] = handler
    }

    fun close() {
        closed = true
        pendingUa.values.forEach { it.countDown() }
        pendingPn.values.forEach { it.countDown() }
        pendingUa.clear()
        pendingPn.clear()
        dataHandlers.clear()
    }

    // ------------------------------------------------------------------
    // Inbound frame handling.
    // ------------------------------------------------------------------

    private fun onRfcommFrame(payload: ByteArray) {
        if (payload.size < 4) return // addr+ctrl+len+fcs minimum
        val dlci = (payload[0].toInt() ushr 2) and 0x3F
        val control = payload[1].toInt() and 0xFF
        var at = 2
        var length = (payload[at].toInt() and 0xFF) ushr 1
        val ea = payload[at].toInt() and 0x01
        at += 1
        if (ea == 0) {
            // Two-byte length; we only sent single-byte, but tolerate it.
            if (at >= payload.size) return
            length = length or ((payload[at].toInt() and 0xFF) shl 7)
            at += 1
        }
        if (at + length + 1 > payload.size) {
            Log.w(TAG, "truncated RFCOMM frame (dlci=$dlci)")
            return
        }
        val data = payload.copyOfRange(at, at + length)
        when (control) {
            RFCOMM_UA -> {
                pendingUa[dlci]?.countDown()
                if (dlci != RFCOMM_DLCI_CONTROL) Log.i(TAG, "UA received (dlci=$dlci)")
            }
            RFCOMM_DM -> {
                Log.w(TAG, "DM received (dlci=$dlci); peer refused")
                pendingUa[dlci]?.countDown()
            }
            RFCOMM_SABM -> {
                // Peer wants a DLC; answer UA (we are acceptor here).
                sendFrame(dlci, RFCOMM_UA)
            }
            RFCOMM_UIH -> {
                if (dlci == RFCOMM_DLCI_CONTROL) {
                    onMcc(data)
                } else {
                    dataHandlers[dlci]?.let { handler ->
                        runCatching { handler(data) }
                            .onFailure { Log.w(TAG, "RFCOMM data handler failed", it) }
                    }
                }
            }
            else -> Log.w(TAG, "unhandled RFCOMM control 0x${control.toString(16)}")
        }
    }

    private fun onMcc(data: ByteArray) {
        if (data.size < 2) return
        val type = data[0].toInt() and 0xFE // mask off C/R
        val len = (data[1].toInt() and 0xFF) ushr 1
        if (2 + len > data.size) return
        val value = data.copyOfRange(2, 2 + len)
        when (type) {
            RFCOMM_MCC_PN -> {
                // Peer PN request: echo it back as the response (accept defaults).
                val rsp = mccFrame(RFCOMM_MCC_PN, value)
                sendFrame(RFCOMM_DLCI_CONTROL, RFCOMM_UIH, rsp)
                // If we have a pending PN for a matching DLCI, release it.
                if (value.isNotEmpty()) {
                    val dlci = value[0].toInt() and 0xFF
                    pendingPn[dlci]?.countDown()
                }
            }
            RFCOMM_MCC_MSC -> {
                // Modem status: acknowledge with our own MSC response.
                val rsp = mccFrame(RFCOMM_MCC_MSC, value)
                sendFrame(RFCOMM_DLCI_CONTROL, RFCOMM_UIH, rsp)
            }
            else -> Log.w(TAG, "unhandled RFCOMM MCC 0x${type.toString(16)}")
        }
    }
}
