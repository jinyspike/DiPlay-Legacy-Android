package com.shilapi.xcertplay.usbbt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HciProtocolTest {

    @Test
    fun encodeResetCommand() {
        // HCI_Reset = OGF 0x03, OCF 0x0003 -> opcode 0x0C03, no params.
        assertArrayEquals(
            byteArrayOf(0x03, 0x0C, 0x00),
            HciProtocol.encodeCommand(HciProtocol.OP_RESET),
        )
        assertEquals(0x0C03, HciProtocol.OP_RESET)
    }

    @Test
    fun encodeCommandWithParams() {
        // Write_Scan_Enable(0x03): opcode 0x0C1A + len 1 + param.
        assertArrayEquals(
            byteArrayOf(0x1A, 0x0C, 0x01, 0x03),
            HciProtocol.encodeCommand(HciProtocol.OP_WRITE_SCAN_ENABLE, byteArrayOf(0x03)),
        )
    }

    @Test
    fun parseCommandCompleteEvent() {
        // 0x04 | 0x0E | len=4 | numPkts=1 | opcode 0x0C03 LE | status=0
        val packet = byteArrayOf(0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00)
        val event = HciProtocol.parseEvent(packet, packet.size)!!
        assertEquals(0x0E, event.code)
        val complete = HciProtocol.parseCommandComplete(event)!!
        assertEquals(1, complete.numHciCommandPackets)
        assertEquals(0x0C03, complete.opcode)
        assertArrayEquals(byteArrayOf(0x00), complete.returnParams)
    }

    @Test
    fun parseCommandStatusEvent() {
        // 0x04 | 0x0D | len=4 | status=0 | numPkts=1 | opcode 0x1009 LE
        val packet = byteArrayOf(0x04, 0x0D, 0x04, 0x00, 0x01, 0x09, 0x10)
        val event = HciProtocol.parseEvent(packet, packet.size)!!
        val status = HciProtocol.parseCommandStatus(event)!!
        assertEquals(0, status.status)
        assertEquals(0x1009, status.opcode)
    }

    @Test
    fun parseMalformedEventsReturnNull() {
        assertNull(HciProtocol.parseEvent(byteArrayOf(0x04, 0x0E), 2)) // truncated header
        assertNull(HciProtocol.parseEvent(byteArrayOf(0x02, 0x0E, 0x00), 3)) // wrong indicator
        // Declared length longer than the bytes we actually read.
        assertNull(HciProtocol.parseEvent(byteArrayOf(0x04, 0x0E, 0x04, 0x01), 4))
        // Command Complete with fewer than 3 param bytes.
        val short = HciProtocol.HciEvent(0x0E, byteArrayOf(0x01, 0x03))
        assertNull(HciProtocol.parseCommandComplete(short))
        // Wrong event code.
        val wrong = HciProtocol.HciEvent(0x0D, byteArrayOf(0x01, 0x03, 0x0C, 0x00))
        assertNull(HciProtocol.parseCommandComplete(wrong))
    }

    @Test
    fun parseBdAddr() {
        // status=0 + 6 address bytes LSB-first: 11:22:33:44:55:66 on the wire as 66 55 44 33 22 11.
        val ret = byteArrayOf(0x00, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11)
        assertEquals("11:22:33:44:55:66", HciProtocol.parseBdAddr(ret))
        assertNull(HciProtocol.parseBdAddr(byteArrayOf(0x01, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11)))
        assertNull(HciProtocol.parseBdAddr(byteArrayOf(0x00, 0x11)))
    }

    @Test
    fun parseBufferSize() {
        // status=0, aclLen=1021 (0x03FD LE), scoLen=255, aclPkts=8, scoPkts=1
        val ret = byteArrayOf(0x00, 0xFD.toByte(), 0x03, 0xFF.toByte(), 0x08, 0x00, 0x01, 0x00)
        val bs = HciProtocol.parseBufferSize(ret)!!
        assertEquals(1021, bs.aclDataPacketLength)
        assertEquals(255, bs.scoDataPacketLength)
        assertEquals(8, bs.totalNumAclPackets)
        assertEquals(1, bs.totalNumScoPackets)
        assertNull(HciProtocol.parseBufferSize(byteArrayOf(0x00, 0x01)))
    }

    @Test
    fun encodeLocalNameIsPaddedTo248() {
        val out = HciProtocol.encodeLocalName("DiPlay")
        assertEquals(248, out.size)
        assertEquals("DiPlay", out.copyOfRange(0, 6).toString(Charsets.UTF_8))
        assertEquals(0, out[247])
        // Over-long names are truncated, never overflow.
        val long = HciProtocol.encodeLocalName("x".repeat(300))
        assertEquals(248, long.size)
    }

    @Test
    fun aclEncodeParseRoundTrip() {
        val data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val packet = HciProtocol.encodeAcl(handle = 0x0042, data = data)
        // 0x02 | handle+flags LE | len LE | data
        assertEquals(0x02, packet[0].toInt() and 0xFF)
        val parsed = HciProtocol.parseAcl(packet)
        assertEquals(0x0042, parsed?.handle)
        assertArrayEquals(data, parsed?.data)
    }

    @Test
    fun aclParseRejectsTruncated() {
        assertNull(HciProtocol.parseAcl(byteArrayOf(0x02, 0x01)))
        // Declared length exceeds buffer.
        assertNull(
            HciProtocol.parseAcl(byteArrayOf(0x02, 0x42, 0x20, 0x10, 0x00, 0x01, 0x02)),
        )
    }

    @Test
    fun l2capEncodeParseRoundTrip() {
        val payload = byteArrayOf(0x0A, 0x0B, 0x0C)
        val frame = HciProtocol.encodeL2cap(cid = 0x0040, payload = payload)
        val parsed = HciProtocol.parseL2cap(frame)
        assertEquals(0x0040, parsed?.cid)
        assertArrayEquals(payload, parsed?.payload)
    }

    @Test
    fun bdAddrEncodeParseRoundTrip() {
        val addr = "A1:B2:C3:D4:E5:F6"
        val wire = HciProtocol.encodeBdAddr(addr)
        // LSB first on the wire.
        assertArrayEquals(
            byteArrayOf(0xF6.toByte(), 0xE5.toByte(), 0xD4.toByte(), 0xC3.toByte(), 0xB2.toByte(), 0xA1.toByte()),
            wire,
        )
        assertEquals(addr, wire?.let { HciProtocol.parseBdAddrBytes(it) })
    }

    @Test
    fun connectionCompleteParse() {
        // 0x04 | 0x03 | len=11 | status=0 | handle=0x0042 LE | BD_ADDR LSB-first | link_type | encrypt
        val packet = byteArrayOf(
            0x04, 0x03, 0x0B, 0x00,
            0x42, 0x00,
            0xF6.toByte(), 0xE5.toByte(), 0xD4.toByte(), 0xC3.toByte(), 0xB2.toByte(), 0xA1.toByte(),
            0x01, 0x00,
        )
        val event = HciProtocol.parseEvent(packet)
        val cc = event?.let { HciProtocol.parseConnectionComplete(it) }
        assertEquals(0, cc?.status)
        assertEquals(0x0042, cc?.handle)
        assertEquals("A1:B2:C3:D4:E5:F6", cc?.bdAddr)
    }

    @Test
    fun rfcommDlciEncoding() {
        // Server channel 1, initiator -> DLCI 3.
        assertEquals(3, HciProtocol.rfcommDlci(1, initiator = true))
        // Server channel 2, acceptor -> DLCI 4.
        assertEquals(4, HciProtocol.rfcommDlci(2, initiator = false))
        assertEquals(HciProtocol.RFCOMM_DLCI_CONTROL, 0)
    }
}
