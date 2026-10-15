package com.shilapi.xcertplay.network

import com.shilapi.xcertplay.transport.EthernetIpv6Codec
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * JVM tests for the user-space wired TCP stack: drives a synthetic iPhone through SYN,
 * handshake, data exchange over the loopback relay, out-of-order duplicate-ACK, and FIN close.
 */
class UserSpaceTcpStackTest {
    private val hostLinkLocal = fe80("2")
    private val phoneLinkLocal = fe80("1")
    private val phoneMac = byteArrayOf(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    private val hostMac = byteArrayOf(0x02, 0x00, 0x00, 0x00, 0x00, 0x02)

    private lateinit var server: ServerSocket
    private lateinit var stack: UserSpaceTcpStack
    private val sentFrames = CopyOnWriteArrayList<ByteArray>()
    private var phoneSeq = 1_000

    @Before
    fun setUp() {
        server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        server.soTimeout = 5_000
        stack = UserSpaceTcpStack(
            hostMac = hostMac,
            hostLinkLocal = hostLinkLocal,
            relayCandidates = listOf(InetAddress.getByName("127.0.0.1")),
            sendFrame = { frame -> sentFrames.add(frame) },
            log = { },
        )
    }

    @After
    fun tearDown() {
        stack.close()
        server.close()
    }

    @Test
    fun handshakeRelaysDataBothWaysAndClosesCleanly() {
        val phonePort = 55_000
        val serverPort = server.localPort

        // SYN → expect SYN-ACK with our MSS advertised.
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq, flags = MiniTcpCodec.SYN, advertiseMss = 1_440))
        val synAck = awaitFrame { it.flags and MiniTcpCodec.SYN != 0 && it.flags and MiniTcpCodec.ACK != 0 }
        assertNotNull("no SYN-ACK in reply", synAck)
        assertEquals(1_001, synAck!!.acknowledgment)
        assertEquals(MiniTcpCodec.OUR_MSS, synAck.maxSegmentSize)
        val iss = synAck.sequence

        // ACK completes the handshake; the stack should connect the loopback relay.
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq + 1, flags = MiniTcpCodec.ACK, ack = iss + 1))
        val accepted: Socket = server.accept()
        accepted.soTimeout = 5_000

        // Phone → car data is delivered through the relay.
        val payload = "hello car".toByteArray()
        inbound(
            buildPhoneSegment(
                phonePort, serverPort, seq = phoneSeq + 1, flags = MiniTcpCodec.ACK or MiniTcpCodec.PSH,
                ack = iss + 1, payload = payload,
            ),
        )
        phoneSeq += payload.size
        val buffer = ByteArray(payload.size)
        var read = 0
        while (read < payload.size) {
            val count = accepted.getInputStream().read(buffer, read, payload.size - read)
            assertTrue("relay stream closed early", count >= 0)
            read += count
        }
        assertEquals("hello car", String(buffer))

        // Car → phone data comes back as segments; ACK them so the retransmit queue drains.
        val reply = "hello phone".toByteArray()
        accepted.getOutputStream().write(reply)
        accepted.getOutputStream().flush()
        val dataSegment = awaitFrame { it.payload.isNotEmpty() }
        assertNotNull("no data segment reached the phone", dataSegment)
        assertEquals(String(reply), String(dataSegment!!.payload))
        val dataSeq = dataSegment.sequence
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq + 1, flags = MiniTcpCodec.ACK, ack = dataSeq + reply.size))

        // Closing the relayed socket sends FIN to the phone.
        accepted.close()
        val fin = awaitFrame { it.hasFin }
        assertNotNull("no FIN reached the phone", fin)
        val finSeqSpace = fin!!.seqSpace
        inbound(
            buildPhoneSegment(
                phonePort, serverPort, seq = phoneSeq + 1,
                flags = MiniTcpCodec.ACK, ack = fin.sequence + finSeqSpace,
            ),
        )
        assertTrue(stack.establishedCount.get() >= 1)
        assertTrue(stack.relayConnected.get() >= 1)
    }

    @Test
    fun outOfOrderSegmentIsDroppedWithDuplicateAck() {
        val phonePort = 55_100
        val serverPort = server.localPort
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq, flags = MiniTcpCodec.SYN, advertiseMss = 1_440))
        val synAck = awaitFrame { it.flags and MiniTcpCodec.SYN != 0 }
        assertNotNull(synAck)
        val iss = synAck!!.sequence
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq + 1, flags = MiniTcpCodec.ACK, ack = iss + 1))
        server.accept()

        val before = sentFrames.size
        // A segment starting past rcvNxt must be dropped and answered with a duplicate ACK.
        inbound(
            buildPhoneSegment(
                phonePort, serverPort, seq = phoneSeq + 21,
                flags = MiniTcpCodec.ACK or MiniTcpCodec.PSH, ack = iss + 1, payload = "late".toByteArray(),
            ),
        )
        val dupAck = awaitFrame(fromIndex = before) { it.hasAck && it.payload.isEmpty() && !it.hasSyn }
        assertNotNull("no duplicate ACK for out-of-order segment", dupAck)
        assertEquals(phoneSeq + 1, dupAck!!.acknowledgment)
    }

    @Test
    fun orphanSynOnClosedPortIsReset() {
        // Nobody listens on this port: the relay connect fails and the phone gets an RST.
        val serverPort = server.localPort + 500
        inbound(buildPhoneSegment(56_000, serverPort, flags = MiniTcpCodec.SYN, advertiseMss = 1_440))
        val rst = awaitFrame { it.hasRst }
        assertNotNull("no RST for orphan SYN on a closed port", rst)
    }

    @Test
    fun zeroWindowProbesThenReopenResumesSending() {
        val phonePort = 55_200
        val serverPort = server.localPort
        // Phone advertises a tiny 4-byte window on the SYN and in the handshake ACK.
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq, flags = MiniTcpCodec.SYN, advertiseMss = 1_440, window = 4))
        val synAck = awaitFrame { it.flags and MiniTcpCodec.SYN != 0 }
        assertNotNull(synAck)
        val iss = synAck!!.sequence
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq + 1, flags = MiniTcpCodec.ACK, ack = iss + 1, window = 4))
        val accepted: Socket = server.accept()

        // Car writes 8 bytes; only the first 4 fit inside the advertised window.
        accepted.getOutputStream().write("abcdefgh".toByteArray())
        accepted.getOutputStream().flush()
        val first = awaitFrame { it.payload.isNotEmpty() }
        assertNotNull("no window-limited data segment", first)
        assertEquals("abcd", String(first!!.payload))
        val dataSeq = first.sequence

        // Phone ACKs those 4 bytes and closes the window to zero: the stack must accept the
        // zero window and emit exactly a 1-byte persist probe from the pending data.
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq + 1, flags = MiniTcpCodec.ACK, ack = dataSeq + 4, window = 0))
        val probe = awaitFrame { it.payload.size == 1 }
        assertNotNull("no zero-window probe sent", probe)
        assertEquals("e", String(probe!!.payload))

        // Phone reopens the window (ACK advancing over the probe): pending data must resume
        // without any further car-side activity.
        inbound(buildPhoneSegment(phonePort, serverPort, seq = phoneSeq + 1, flags = MiniTcpCodec.ACK, ack = probe.sequence + 1, window = 1_000))
        val resumed = awaitFrame { String(it.payload) == "fgh" }
        assertNotNull("no data after window reopened", resumed)
        accepted.close()
    }

    @Test
    fun builtSegmentsCarryValidTcpChecksum() {
        // SYN-ACK style segment carrying the MSS option.
        val synAck = MiniTcpCodec.buildSegment(
            sourceIp = hostLinkLocal, destinationIp = phoneLinkLocal,
            sourcePort = 7000, destinationPort = 55_000,
            sequence = 1, acknowledgment = 2,
            flags = MiniTcpCodec.SYN or MiniTcpCodec.ACK, window = 65_535,
            advertiseMss = MiniTcpCodec.OUR_MSS,
        )
        assertTrue("checksum invalid on SYN-ACK", tcpChecksumValid(synAck))
        // Data segment with an odd payload length (exercises the final-byte checksum padding).
        val data = MiniTcpCodec.buildSegment(
            sourceIp = hostLinkLocal, destinationIp = phoneLinkLocal,
            sourcePort = 7000, destinationPort = 55_000,
            sequence = 3, acknowledgment = 4,
            flags = MiniTcpCodec.ACK or MiniTcpCodec.PSH, window = 65_535,
            payload = "odd".toByteArray(),
        )
        assertTrue("checksum invalid on data segment", tcpChecksumValid(data))
    }

    // ---------------------------------------------------------------- helpers

    private fun inbound(packet: ByteArray) {
        val handled = stack.onInboundPacket(packet, phoneMac)
        assertTrue("stack refused an inbound packet", handled)
    }

    /** Builds one IPv6 packet as the iPhone would send it over the NCM link. */
    private fun buildPhoneSegment(
        phonePort: Int,
        carPort: Int,
        seq: Int = phoneSeq + 1,
        ack: Int = 0,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        advertiseMss: Int? = null,
        window: Int = 65_535,
    ): ByteArray = MiniTcpCodec.buildSegment(
        sourceIp = phoneLinkLocal, destinationIp = hostLinkLocal,
        sourcePort = phonePort, destinationPort = carPort,
        sequence = seq, acknowledgment = ack,
        flags = flags, window = window,
        payload = payload, advertiseMss = advertiseMss,
    )

    /** Parses one captured Ethernet frame back into a TCP segment view. */
    private fun parseCaptured(frame: ByteArray): MiniTcpCodec.Segment? {
        val ipv6 = EthernetIpv6Codec.parseIpv6(frame)?.ipv6 ?: return null
        return MiniTcpCodec.parse(ipv6)
    }

    /** Waits for a captured frame (at or after [fromIndex]) matching [predicate]. */
    private fun awaitFrame(
        fromIndex: Int = 0,
        timeoutMillis: Long = 5_000,
        predicate: (MiniTcpCodec.Segment) -> Boolean,
    ): MiniTcpCodec.Segment? {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var scanned = fromIndex
        while (System.currentTimeMillis() < deadline) {
            while (scanned < sentFrames.size) {
                val segment = parseCaptured(sentFrames[scanned])
                scanned += 1
                if (segment != null && predicate(segment)) return segment
            }
            Thread.sleep(25)
        }
        return null
    }

    private fun fe80(host: String): ByteArray {
        val bytes = ByteArray(16)
        bytes[0] = 0xfe.toByte()
        bytes[1] = 0x80.toByte()
        bytes[15] = host.toLong(16).toByte()
        return bytes
    }

    /**
     * Independent TCP checksum verification over the IPv6 pseudo-header plus the whole TCP
     * segment (16-bit ones' complement sum, folded and inverted). The checksum field itself
     * is zeroed first (standard verification procedure) and the codec is re-implemented here
     * so a regression in [MiniTcpCodec.buildSegment] cannot hide behind itself.
     */
    private fun tcpChecksumValid(packet: ByteArray): Boolean {
        val copy = packet.copyOf()
        copy[56] = 0
        copy[57] = 0
        val tcpLength = ((copy[4].toInt() and 0xff) shl 8) or (copy[5].toInt() and 0xff)
        var sum = 0
        var index = 8
        while (index < 40) { // pseudo-header: source + destination
            sum += ((copy[index].toInt() and 0xff) shl 8) or (copy[index + 1].toInt() and 0xff)
            index += 2
        }
        sum += 6 + tcpLength // next header + TCP length
        val end = 40 + tcpLength
        index = 40
        while (index + 1 < end) {
            sum += ((copy[index].toInt() and 0xff) shl 8) or (copy[index + 1].toInt() and 0xff)
            index += 2
        }
        if (index < end) sum += (copy[index].toInt() and 0xff) shl 8 // odd final byte
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        val actual = ((packet[56].toInt() and 0xff) shl 8) or (packet[57].toInt() and 0xff)
        return actual == (sum.inv() and 0xffff)
    }
}
