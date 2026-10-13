package com.shilapi.xcertplay.usbbt

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.util.Log
import com.shilapi.xcertplay.usbbt.HciProtocol.EVT_COMMAND_COMPLETE
import com.shilapi.xcertplay.usbbt.HciProtocol.EVT_COMMAND_STATUS
import com.shilapi.xcertplay.usbbt.HciProtocol.MAX_EVENT_PACKET_SIZE
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_READ_BD_ADDR
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_READ_BUFFER_SIZE
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_READ_LOCAL_VERSION
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_RESET
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_WRITE_LOCAL_NAME
import com.shilapi.xcertplay.usbbt.HciProtocol.OP_WRITE_SCAN_ENABLE
import com.shilapi.xcertplay.usbbt.HciProtocol.SCAN_INQUIRY_AND_PAGE
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_BT_CONTROL_REQUEST
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_BT_REQ_TYPE_CLASS_INTERFACE_OUT
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_CLASS_WIRELESS_CONTROLLER
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_PROTOCOL_BLUETOOTH
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_SUBCLASS_RF
import com.shilapi.xcertplay.usbbt.HciProtocol.encodeCommand
import com.shilapi.xcertplay.usbbt.HciProtocol.encodeLocalName
import com.shilapi.xcertplay.usbbt.HciProtocol.parseBdAddr
import com.shilapi.xcertplay.usbbt.HciProtocol.parseBufferSize
import com.shilapi.xcertplay.usbbt.HciProtocol.parseCommandComplete
import com.shilapi.xcertplay.usbbt.HciProtocol.parseCommandStatus
import com.shilapi.xcertplay.usbbt.HciProtocol.parseEvent

/**
 * HCI transport for a USB Bluetooth dongle (Phase 2).
 *
 * Mapping (Bluetooth Core Spec Vol 4, Part B):
 * - HCI commands  -> USB control transfer on endpoint 0
 *                     (bmRequestType=0x20, bRequest=0, wValue=0, wIndex=interface)
 * - HCI events    -> interrupt IN endpoint
 * - ACL data      -> bulk IN / bulk OUT endpoints
 *
 * Every public method blocks the calling thread; call from a background thread.
 * Create via [open]; always [close] when done.
 *
 * Clean-room: transport mapping and init sequence derived from the public
 * Bluetooth specification only.
 */
class UsbBtHci private constructor(
    val device: UsbDevice,
    private val connection: UsbDeviceConnection,
    private val btInterface: UsbInterface,
    private val eventEndpoint: UsbEndpoint,
    private val aclInEndpoint: UsbEndpoint,
    private val aclOutEndpoint: UsbEndpoint,
) : AutoCloseable {

    /** Outcome of an HCI operation. */
    sealed class HciResult<out T> {
        data class Ok<T>(val value: T) : HciResult<T>()
        data class Failed(val reason: String) : HciResult<Nothing>()
    }

    /** Result of [initialize]. */
    data class InitResult(
        val bdAddr: String?,
        val bufferSize: HciProtocol.BufferSize?,
        /** Human-readable step log for diagnostics. */
        val steps: List<String>,
    )

    companion object {
        private const val TAG = "UsbBtHci"
        private const val DEFAULT_COMMAND_TIMEOUT_MS = 2_000
        private const val EVENT_READ_SLICE_MS = 500

        /**
         * Open [device] for HCI: finds the Bluetooth interface, claims it and
         * locates the interrupt/bulk endpoints. Returns null with a log when
         * the device has no usable Bluetooth interface or endpoints.
         *
         * The caller must hold USB permission for [device].
         */
        fun open(usbManager: UsbManager, device: UsbDevice): UsbBtHci? {
            val btInterface = findBluetoothInterface(device)
                ?: run {
                    Log.w(TAG, "no Bluetooth interface on vid=0x${device.vendorId.toString(16)}")
                    return null
                }
            val connection = usbManager.openDevice(device)
                ?: run {
                    Log.w(TAG, "openDevice failed")
                    return null
                }
            var opened: UsbBtHci? = null
            try {
                if (!connection.claimInterface(btInterface, true)) {
                    Log.w(TAG, "claimInterface failed for interface ${btInterface.id}")
                    return null
                }
                val endpoints = findEndpoints(btInterface)
                if (endpoints == null) {
                    Log.w(TAG, "missing interrupt/bulk endpoints on interface ${btInterface.id}")
                    return null
                }
                Log.i(
                    TAG,
                    "HCI opened: interface=${btInterface.id} " +
                        "evtEp=${endpoints.event.address} aclIn=${endpoints.aclIn.address} " +
                        "aclOut=${endpoints.aclOut.address}",
                )
                opened = UsbBtHci(
                    device = device,
                    connection = connection,
                    btInterface = btInterface,
                    eventEndpoint = endpoints.event,
                    aclInEndpoint = endpoints.aclIn,
                    aclOutEndpoint = endpoints.aclOut,
                )
            } catch (t: Throwable) {
                Log.w(TAG, "open failed", t)
            } finally {
                if (opened == null) {
                    runCatching { connection.releaseInterface(btInterface) }
                    runCatching { connection.close() }
                }
            }
            return opened
        }

        private data class Endpoints(
            val event: UsbEndpoint,
            val aclIn: UsbEndpoint,
            val aclOut: UsbEndpoint,
        )

        private fun findBluetoothInterface(device: UsbDevice): UsbInterface? {
            for (i in 0 until device.interfaceCount) {
                val intf = device.getInterface(i)
                if (intf.interfaceClass == USB_CLASS_WIRELESS_CONTROLLER &&
                    intf.interfaceSubclass == USB_SUBCLASS_RF &&
                    intf.interfaceProtocol == USB_PROTOCOL_BLUETOOTH
                ) {
                    return intf
                }
            }
            // Fallback: some dongles only tag the device descriptor; interface 0
            // is the HCI control interface on virtually all of them.
            return if (device.interfaceCount > 0) device.getInterface(0) else null
        }

        private fun findEndpoints(intf: UsbInterface): Endpoints? {
            var event: UsbEndpoint? = null
            var aclIn: UsbEndpoint? = null
            var aclOut: UsbEndpoint? = null
            for (i in 0 until intf.endpointCount) {
                val ep = intf.getEndpoint(i)
                val isIn = ep.direction == UsbConstants.USB_DIR_IN
                when (ep.type) {
                    UsbConstants.USB_ENDPOINT_XFER_INT -> if (isIn && event == null) event = ep
                    UsbConstants.USB_ENDPOINT_XFER_BULK -> {
                        if (isIn && aclIn == null) aclIn = ep
                        if (!isIn && aclOut == null) aclOut = ep
                    }
                    else -> { /* isochronous (SCO audio) not needed for CarPlay data path */ }
                }
            }
            val e = event ?: return null
            val inEp = aclIn ?: return null
            val outEp = aclOut ?: return null
            return Endpoints(e, inEp, outEp)
        }
    }

    /**
     * Send an HCI command and wait for its Command Complete (or a failing
     * Command Status). Returns the command's return parameters on success.
     */
    fun sendCommand(
        opcode: Int,
        params: ByteArray = byteArrayOf(),
        timeoutMs: Int = DEFAULT_COMMAND_TIMEOUT_MS,
    ): HciResult<ByteArray> {
        val payload = runCatching { encodeCommand(opcode, params) }.getOrElse {
            return HciResult.Failed("encode failed: ${it.message}")
        }
        val sent = connection.controlTransfer(
            USB_BT_REQ_TYPE_CLASS_INTERFACE_OUT,
            USB_BT_CONTROL_REQUEST,
            0,
            btInterface.id,
            payload,
            payload.size,
            timeoutMs,
        )
        if (sent != payload.size) {
            return HciResult.Failed(
                "control transfer sent $sent/${payload.size} bytes for opcode 0x${opcode.toString(16)}",
            )
        }
        val deadline = System.currentTimeMillis() + timeoutMs
        val buf = ByteArray(MAX_EVENT_PACKET_SIZE)
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) {
                return HciResult.Failed(
                    "timeout waiting for Command Complete (opcode 0x${opcode.toString(16)})",
                )
            }
            val read = connection.bulkTransfer(
                eventEndpoint,
                buf,
                buf.size,
                remaining.coerceAtMost(EVENT_READ_SLICE_MS.toLong()).toInt(),
            )
            if (read < 0) continue // timeout slice elapsed; re-check the deadline
            val event = parseEvent(buf, read) ?: continue
            when (event.code) {
                EVT_COMMAND_COMPLETE -> {
                    val complete = parseCommandComplete(event) ?: continue
                    if (complete.opcode != opcode) continue // not ours; keep waiting
                    val status = complete.returnParams.firstOrNull()?.toInt()?.and(0xFF) ?: 0xFF
                    if (status != 0) {
                        return HciResult.Failed(
                            "Command Complete status=0x${status.toString(16)} " +
                                "for opcode 0x${opcode.toString(16)}",
                        )
                    }
                    return HciResult.Ok(complete.returnParams)
                }
                EVT_COMMAND_STATUS -> {
                    val status = parseCommandStatus(event) ?: continue
                    if (status.opcode != opcode) continue
                    if (status.status != 0) {
                        return HciResult.Failed(
                            "Command Status=0x${status.status.toString(16)} " +
                                "for opcode 0x${opcode.toString(16)}",
                        )
                    }
                    // Command accepted; its Command Complete will follow below.
                }
                else -> { /* unrelated async event; ignore while waiting */ }
            }
        }
    }

    /**
     * Minimal bring-up so the dongle becomes usable and discoverable:
     * Reset -> Read_Local_Version -> Read_BD_ADDR -> Read_Buffer_Size ->
     * Write_Scan_Enable(inquiry+page) -> Write_Local_Name.
     *
     * Note: several Broadcom/Realtek dongles need vendor firmware uploaded
     * before they answer usefully; if Reset itself fails the log will say so
     * and firmware loading (future phase) is the next step.
     */
    fun initialize(localName: String = "DiPlay"): HciResult<InitResult> {
        val steps = mutableListOf<String>()
        fun step(text: String) {
            steps.add(text)
            Log.i(TAG, text)
        }

        val reset = sendCommand(OP_RESET)
        if (reset is HciResult.Failed) {
            return HciResult.Failed("HCI_Reset failed: ${reset.reason}; dongle may need firmware")
        }
        step("HCI_Reset ok")

        when (val version = sendCommand(OP_READ_LOCAL_VERSION)) {
            is HciResult.Ok -> step("Local_Version ok (${version.value.size} return bytes)")
            is HciResult.Failed -> step("Local_Version failed: ${version.reason}")
        }

        val bdAddr = when (val addr = sendCommand(OP_READ_BD_ADDR)) {
            is HciResult.Ok -> parseBdAddr(addr.value)?.also { step("BD_ADDR=$it") }
                ?: run { step("Read_BD_ADDR returned malformed address"); null }
            is HciResult.Failed -> {
                step("Read_BD_ADDR failed: ${addr.reason}")
                return HciResult.Failed("Read_BD_ADDR failed: ${addr.reason}")
            }
        }

        val bufferSize = when (val bs = sendCommand(OP_READ_BUFFER_SIZE)) {
            is HciResult.Ok -> parseBufferSize(bs.value)?.also {
                step("Buffer_Size aclLen=${it.aclDataPacketLength} aclPkts=${it.totalNumAclPackets}")
            }
            is HciResult.Failed -> {
                step("Read_Buffer_Size failed: ${bs.reason}")
                null
            }
        }

        val scan = sendCommand(OP_WRITE_SCAN_ENABLE, byteArrayOf(SCAN_INQUIRY_AND_PAGE.toByte()))
        if (scan is HciResult.Failed) {
            return HciResult.Failed("Write_Scan_Enable failed: ${scan.reason}")
        }
        step("Scan_Enable inquiry+page ok")

        val name = sendCommand(OP_WRITE_LOCAL_NAME, encodeLocalName(localName))
        if (name is HciResult.Failed) {
            step("Write_Local_Name failed (non-fatal): ${name.reason}")
        } else {
            step("Local_Name=$localName ok")
        }

        return HciResult.Ok(InitResult(bdAddr = bdAddr, bufferSize = bufferSize, steps = steps))
    }

    override fun close() {
        runCatching { connection.releaseInterface(btInterface) }
        runCatching { connection.close() }
        Log.i(TAG, "HCI closed")
    }

    /**
     * Send an L2CAP packet (already framed by [HciProtocol.encodeL2cap]) over
     * the ACL bulk-OUT endpoint. Returns false when the transfer failed.
     *
     * Phase 3: used by the L2CAP layer. Blocking; call from a background thread.
     */
    fun sendAcl(handle: Int, l2capPacket: ByteArray, timeoutMs: Int = 2_000): Boolean {
        val packet = runCatching { HciProtocol.encodeAcl(handle, l2capPacket) }.getOrElse {
            Log.w(TAG, "ACL encode failed: ${it.message}")
            return false
        }
        val sent = connection.bulkTransfer(aclOutEndpoint, packet, packet.size, timeoutMs)
        if (sent != packet.size) {
            Log.w(TAG, "ACL bulkTransfer sent $sent/${packet.size}")
            return false
        }
        return true
    }

    /**
     * Read one HCI ACL packet from the bulk-IN endpoint. Returns null on
     * timeout or when the packet is malformed. Blocking up to [timeoutMs].
     *
     * Phase 3: the L2CAP layer polls this in its receive loop.
     */
    fun pollAcl(timeoutMs: Int = 500): HciProtocol.AclPacket? {
        val buf = ByteArray(1024)
        val read = connection.bulkTransfer(aclInEndpoint, buf, buf.size, timeoutMs)
        if (read <= 0) return null
        return HciProtocol.parseAcl(buf, read)
    }

    /**
     * Poll one HCI event without consuming it for a pending command.
     * Used by the connection/pairing machinery for async events
     * (Connection Complete, IO Capability Request, ...).
     */
    fun pollEvent(timeoutMs: Int = 500): HciProtocol.HciEvent? {
        val buf = ByteArray(MAX_EVENT_PACKET_SIZE)
        val read = connection.bulkTransfer(eventEndpoint, buf, buf.size, timeoutMs)
        if (read <= 0) return null
        return HciProtocol.parseEvent(buf, read)
    }
}
