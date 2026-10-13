package com.shilapi.xcertplay.usbbt

/**
 * Bluetooth HCI/USB transport protocol constants, packet encoding and parsing.
 *
 * Pure Kotlin with no Android dependencies, so it is unit-testable on the JVM.
 * Based on the Bluetooth Core Specification:
 * - Vol 4, Part B (USB Transport Layer): HCI commands travel as USB control
 *   transfers on endpoint 0 (bmRequestType=0x20, bRequest=0); HCI events arrive
 *   on the interrupt IN endpoint; ACL data uses bulk IN/OUT endpoints.
 * - Vol 4, Part E (HCI): command/event packet formats and opcodes.
 *
 * Clean-room implementation: derived from the public spec, not from any
 * third-party code.
 */
object HciProtocol {

    // USB transport: HCI commands are sent with a class-specific control transfer.
    const val USB_BT_REQ_TYPE_CLASS_INTERFACE_OUT = 0x20
    const val USB_BT_CONTROL_REQUEST = 0x00

    // USB-IF "Wireless Controller" class codes identifying a Bluetooth dongle.
    const val USB_CLASS_WIRELESS_CONTROLLER = 0xE0
    const val USB_SUBCLASS_RF = 0x01
    const val USB_PROTOCOL_BLUETOOTH = 0x01

    // HCI packet indicators as seen on interrupt/bulk endpoints.
    const val HCI_EVENT_PACKET = 0x04
    const val HCI_ACL_PACKET = 0x02

    // HCI event codes we care about during init.
    const val EVT_COMMAND_COMPLETE = 0x0E
    const val EVT_COMMAND_STATUS = 0x0D

    /** HCI opcode = (OGF << 10) | OCF. */
    fun opcode(ogf: Int, ocf: Int): Int = (ogf shl 10) or ocf

    val OP_RESET = opcode(0x03, 0x0003)
    val OP_READ_LOCAL_VERSION = opcode(0x04, 0x0001)
    val OP_READ_BD_ADDR = opcode(0x04, 0x0009)
    val OP_READ_BUFFER_SIZE = opcode(0x04, 0x0005)
    val OP_WRITE_SCAN_ENABLE = opcode(0x03, 0x001A)
    val OP_WRITE_LOCAL_NAME = opcode(0x03, 0x0013)

    // Write_Scan_Enable values.
    const val SCAN_DISABLED = 0x00
    const val SCAN_INQUIRY_AND_PAGE = 0x03

    /** Max bytes of a single HCI event packet on the wire (indicator + header + 255 params). */
    const val MAX_EVENT_PACKET_SIZE = 260

    /**
     * Encode an HCI command for the USB control transfer payload:
     * opcode (2 bytes LE) + total param length (1 byte) + params.
     * The 0x01 packet indicator is NOT included; the control transfer wraps it.
     */
    fun encodeCommand(opcode: Int, params: ByteArray = byteArrayOf()): ByteArray {
        require(params.size <= 255) { "HCI params too long: ${params.size}" }
        val out = ByteArray(3 + params.size)
        out[0] = (opcode and 0xFF).toByte()
        out[1] = ((opcode ushr 8) and 0xFF).toByte()
        out[2] = params.size.toByte()
        params.copyInto(out, 3)
        return out
    }

    /** One parsed HCI event packet. */
    data class HciEvent(val code: Int, val params: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HciEvent) return false
            return code == other.code && params.contentEquals(other.params)
        }

        override fun hashCode(): Int = 31 * code + params.contentHashCode()
    }

    /** Parsed Command Complete (0x0E) event. */
    data class CommandComplete(
        val numHciCommandPackets: Int,
        val opcode: Int,
        val returnParams: ByteArray,
    )

    /** Parsed Command Status (0x0D) event. */
    data class CommandStatus(
        val status: Int,
        val numHciCommandPackets: Int,
        val opcode: Int,
    )

    /**
     * Parse one HCI event packet: 0x04 | event_code | param_len | params.
     * Returns null when [length] bytes do not hold a well-formed event.
     */
    fun parseEvent(packet: ByteArray, length: Int = packet.size): HciEvent? {
        if (length < 3 || length > packet.size) return null
        if (packet[0].toInt() and 0xFF != HCI_EVENT_PACKET) return null
        val paramLen = packet[2].toInt() and 0xFF
        if (3 + paramLen > length) return null
        return HciEvent(
            code = packet[1].toInt() and 0xFF,
            params = packet.copyOfRange(3, 3 + paramLen),
        )
    }

    /** Parse Command Complete (0x0E) params. Null when malformed. */
    fun parseCommandComplete(event: HciEvent): CommandComplete? {
        if (event.code != EVT_COMMAND_COMPLETE || event.params.size < 3) return null
        val opcode = (event.params[1].toInt() and 0xFF) or
            ((event.params[2].toInt() and 0xFF) shl 8)
        return CommandComplete(
            numHciCommandPackets = event.params[0].toInt() and 0xFF,
            opcode = opcode,
            returnParams = event.params.copyOfRange(3, event.params.size),
        )
    }

    /** Parse Command Status (0x0D) params. Null when malformed. */
    fun parseCommandStatus(event: HciEvent): CommandStatus? {
        if (event.code != EVT_COMMAND_STATUS || event.params.size < 4) return null
        val opcode = (event.params[2].toInt() and 0xFF) or
            ((event.params[3].toInt() and 0xFF) shl 8)
        return CommandStatus(
            status = event.params[0].toInt() and 0xFF,
            numHciCommandPackets = event.params[1].toInt() and 0xFF,
            opcode = opcode,
        )
    }

    /**
     * Parse a Read_BD_ADDR return: status(1) + 6-byte address (LSB first on the wire).
     * Returns "XX:XX:XX:XX:XX:XX" (MSB first) or null when status != 0 / malformed.
     */
    fun parseBdAddr(returnParams: ByteArray): String? {
        if (returnParams.size < 7 || returnParams[0] != 0.toByte()) return null
        return (5 downTo 0).joinToString(":") { i ->
            "%02X".format(returnParams[1 + i])
        }
    }

    /** Parsed Read_Buffer_Size return. */
    data class BufferSize(
        val aclDataPacketLength: Int,
        val scoDataPacketLength: Int,
        val totalNumAclPackets: Int,
        val totalNumScoPackets: Int,
    )

    /** Parse Read_Buffer_Size return: status(1) + ACL len(2) + SCO len(1) + ACL pkts(2) + SCO pkts(2). */
    fun parseBufferSize(returnParams: ByteArray): BufferSize? {
        if (returnParams.size < 8 || returnParams[0] != 0.toByte()) return null
        fun u16(at: Int): Int =
            (returnParams[at].toInt() and 0xFF) or ((returnParams[at + 1].toInt() and 0xFF) shl 8)
        return BufferSize(
            aclDataPacketLength = u16(1),
            scoDataPacketLength = returnParams[3].toInt() and 0xFF,
            totalNumAclPackets = u16(4),
            totalNumScoPackets = u16(6),
        )
    }

    /** Encode a Write_Local_Name payload: up to 248 bytes, NUL-padded. */
    fun encodeLocalName(name: String): ByteArray {
        val raw = name.toByteArray(Charsets.UTF_8)
        val out = ByteArray(248)
        raw.copyInto(out, 0, 0, minOf(raw.size, out.size))
        return out
    }

    // ------------------------------------------------------------------
    // HCI ACL data packets (Phase 3).
    // ------------------------------------------------------------------

    /** Parsed HCI ACL data packet. */
    data class AclPacket(val handle: Int, val flags: Int, val data: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AclPacket) return false
            return handle == other.handle && flags == other.flags && data.contentEquals(other.data)
        }

        override fun hashCode(): Int = 31 * (31 * handle + flags) + data.contentHashCode()
    }

    /** PB flag: first fragment of an L2CAP packet (start). */
    const val ACL_PB_FIRST_FLUSHABLE = 0x02

    /**
     * Parse one HCI ACL packet: 0x02 | handle+flags (2 LE) | data_len (2 LE) | data.
     * Returns null when [length] bytes do not hold a well-formed packet.
     */
    fun parseAcl(packet: ByteArray, length: Int = packet.size): AclPacket? {
        if (length < 5 || length > packet.size) return null
        if (packet[0].toInt() and 0xFF != HCI_ACL_PACKET) return null
        val handleFlags = (packet[1].toInt() and 0xFF) or ((packet[2].toInt() and 0xFF) shl 8)
        val dataLen = (packet[3].toInt() and 0xFF) or ((packet[4].toInt() and 0xFF) shl 8)
        if (5 + dataLen > length) return null
        return AclPacket(
            handle = handleFlags and 0x0FFF,
            flags = (handleFlags ushr 12) and 0x0F,
            data = packet.copyOfRange(5, 5 + dataLen),
        )
    }

    /**
     * Encode an HCI ACL packet: 0x02 | handle+PB (2 LE) | data_len (2 LE) | data.
     */
    fun encodeAcl(handle: Int, data: ByteArray): ByteArray {
        val out = ByteArray(5 + data.size)
        out[0] = HCI_ACL_PACKET.toByte()
        val handleFlags = (handle and 0x0FFF) or (ACL_PB_FIRST_FLUSHABLE shl 12)
        out[1] = (handleFlags and 0xFF).toByte()
        out[2] = ((handleFlags ushr 8) and 0xFF).toByte()
        out[3] = (data.size and 0xFF).toByte()
        out[4] = ((data.size ushr 8) and 0xFF).toByte()
        data.copyInto(out, 5)
        return out
    }

    // ------------------------------------------------------------------
    // HCI events needed for BR/EDR connection management (Phase 3/4).
    // ------------------------------------------------------------------
    const val EVT_CONNECTION_COMPLETE = 0x03
    const val EVT_DISCONNECTION_COMPLETE = 0x05
    const val EVT_NUM_COMPLETED_PACKETS = 0x13
    const val EVT_IO_CAPABILITY_REQUEST = 0x31
    const val EVT_USER_CONFIRMATION_REQUEST = 0x33
    const val EVT_SIMPLE_PAIRING_COMPLETE = 0x36
    const val EVT_LINK_KEY_NOTIFICATION = 0x18

    val OP_CREATE_CONNECTION = opcode(0x01, 0x0005)
    val OP_DISCONNECT = opcode(0x01, 0x0006)
    val OP_IO_CAPABILITY_REQUEST_REPLY = opcode(0x01, 0x002B)
    val OP_USER_CONFIRMATION_REQUEST_REPLY = opcode(0x01, 0x002C)
    val OP_WRITE_SIMPLE_PAIRING_MODE = opcode(0x03, 0x0056)
    val OP_SET_EVENT_MASK = opcode(0x03, 0x0001)

    // IO capability values (for IO_Capability_Request_Reply).
    const val IO_CAP_DISPLAY_ONLY = 0x00
    const val IO_CAP_NO_INPUT_NO_OUTPUT = 0x03

    // ------------------------------------------------------------------
    // L2CAP (Bluetooth Core Spec Vol 3, Part A).
    // ------------------------------------------------------------------
    const val L2CAP_CID_SIGNALING = 0x0001
    const val L2CAP_PSM_SDP = 0x0001
    const val L2CAP_PSM_RFCOMM = 0x0003

    // L2CAP signaling command codes.
    const val L2CAP_CMD_CONNECTION_REQ = 0x02
    const val L2CAP_CMD_CONNECTION_RSP = 0x03
    const val L2CAP_CMD_CONFIG_REQ = 0x04
    const val L2CAP_CMD_CONFIG_RSP = 0x05
    const val L2CAP_CMD_DISCONNECTION_REQ = 0x06
    const val L2CAP_CMD_DISCONNECTION_RSP = 0x07

    // L2CAP Connection Response result codes.
    const val L2CAP_CONN_SUCCESS = 0x0000
    const val L2CAP_CONN_PENDING = 0x0001

    /**
     * Encode an L2CAP packet: length (2 LE) | CID (2 LE) | payload.
     * Length covers the payload only (not the 4-byte header).
     */
    fun encodeL2cap(cid: Int, payload: ByteArray): ByteArray {
        val out = ByteArray(4 + payload.size)
        out[0] = (payload.size and 0xFF).toByte()
        out[1] = ((payload.size ushr 8) and 0xFF).toByte()
        out[2] = (cid and 0xFF).toByte()
        out[3] = ((cid ushr 8) and 0xFF).toByte()
        payload.copyInto(out, 4)
        return out
    }

    /** Parsed L2CAP packet. Null when malformed. */
    data class L2capPacket(val cid: Int, val payload: ByteArray)

    fun parseL2cap(data: ByteArray): L2capPacket? {
        if (data.size < 4) return null
        val length = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
        if (4 + length > data.size) return null
        val cid = (data[2].toInt() and 0xFF) or ((data[3].toInt() and 0xFF) shl 8)
        return L2capPacket(cid = cid, payload = data.copyOfRange(4, 4 + length))
    }

    // ------------------------------------------------------------------
    // RFCOMM (Bluetooth Core Spec, RFCOMM with TS 07.10).
    // ------------------------------------------------------------------

    /** RFCOMM frame types. */
    const val RFCOMM_SABM = 0x2F
    const val RFCOMM_UA = 0x63
    const val RFCOMM_DM = 0x0F
    const val RFCOMM_UIH = 0xEF
    const val RFCOMM_MCC = 0x33

    /** RFCOMM MCC message types. */
    const val RFCOMM_MCC_PN = 0x20
    const val RFCOMM_MCC_MSC = 0x38

    /** DLCI 0 is the RFCOMM session control channel. */
    const val RFCOMM_DLCI_CONTROL = 0

    /** RFCOMM server channel from a DLCI: dlci = channel * 2 (+1 for initiator). */
    fun rfcommDlci(serverChannel: Int, initiator: Boolean): Int =
        serverChannel * 2 + if (initiator) 1 else 0

    // ------------------------------------------------------------------
    // SDP (Bluetooth Core Spec Vol 3, Part B).
    // ------------------------------------------------------------------
    const val SDP_PDU_SERVICE_SEARCH_ATTR_REQ = 0x06
    const val SDP_PDU_SERVICE_SEARCH_ATTR_RSP = 0x07

    /** iAP2 service class UUID (128-bit). Public CarPlay accessory UUID. */
    val IAP2_UUID_BYTES: ByteArray = byteArrayOf(
        0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x00.toByte(), 0x00.toByte(), 0x10.toByte(), 0x00.toByte(),
        0x80.toByte(), 0x00.toByte(), 0x00.toByte(), 0x80.toByte(),
        0x5F.toByte(), 0x9B.toByte(), 0x34.toByte(), 0xFB.toByte(),
    )

    // ------------------------------------------------------------------
    // BR/EDR connection management (Phase 5).
    // ------------------------------------------------------------------

    /**
     * Parse a BD_ADDR from the first 6 bytes (LSB first on the wire).
     * Returns "XX:XX:XX:XX:XX:XX" (MSB first) or null when too short.
     */
    fun parseBdAddrBytes(data: ByteArray, at: Int = 0): String? {
        if (at + 6 > data.size) return null
        return (5 downTo 0).joinToString(":") { i ->
            "%02X".format(data[at + i])
        }
    }

    /**
     * Encode a "XX:XX:XX:XX:XX:XX" address to 6 wire bytes (LSB first).
     * Returns null when malformed.
     */
    fun encodeBdAddr(address: String): ByteArray? {
        val parts = address.split(":")
        if (parts.size != 6) return null
        return runCatching {
            ByteArray(6) { i -> parts[5 - i].toInt(16).toByte() }
        }.getOrNull()
    }

    /**
     * Encode HCI_Create_Connection params: BD_ADDR(6) | packet_type(2)=0xCC18
     * | page_scan_repetition_mode(1)=1 | reserved(1)=0 | clock_offset(2)=0
     * | allow_role_switch(1)=1.
     */
    fun encodeCreateConnection(bdAddr: ByteArray): ByteArray {
        require(bdAddr.size == 6) { "BD_ADDR must be 6 bytes" }
        return bdAddr +
            byteArrayOf(0x18.toByte(), 0xCC.toByte(), 0x01, 0x00, 0x00, 0x00, 0x01)
    }

    /** Parsed Connection Complete (0x03) event. */
    data class ConnectionComplete(
        val status: Int,
        val handle: Int,
        val bdAddr: String?,
    )

    /** Parse Connection Complete: status(1) | handle(2) | BD_ADDR(6) | link_type(1) | encryption(1). */
    fun parseConnectionComplete(event: HciEvent): ConnectionComplete? {
        if (event.code != EVT_CONNECTION_COMPLETE || event.params.size < 11) return null
        val handle = (event.params[1].toInt() and 0xFF) or
            ((event.params[2].toInt() and 0xFF) shl 8) and 0x0FFF
        return ConnectionComplete(
            status = event.params[0].toInt() and 0xFF,
            handle = handle,
            bdAddr = parseBdAddrBytes(event.params, 3),
        )
    }

    /** Encode HCI_Disconnect: handle(2) | reason(1)=0x13 (remote user terminated). */
    fun encodeDisconnect(handle: Int): ByteArray =
        byteArrayOf(
            (handle and 0xFF).toByte(),
            ((handle ushr 8) and 0xFF).toByte(),
            0x13,
        )
}
