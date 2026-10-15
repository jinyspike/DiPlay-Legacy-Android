package com.shilapi.xcertplay.network

/**
 * Minimal IPv6/TCP wire codec for the user-space wired TCP stack.
 *
 * The T3 (Android 4.4.2) kernel silently drops the iPhone's TCP SYN before it can match the
 * listening socket (issues #133/#152/#163), so the whole TCP leg for the wired AirPlay link is
 * terminated in-process instead. This object holds the pure wire-format helpers so the state
 * machine in [UserSpaceTcpStack] stays readable and both stay unit-testable on the JVM without
 * any Android dependency.
 *
 * Only what the wired CarPlay link needs is implemented: no IPv6 extension headers (the iPhone
 * sends TCP directly after the fixed 40-byte header), no TCP options other than MSS, no window
 * scaling (omitting WS in the SYN-ACK disables it per RFC 7323, keeping window fields in bytes).
 */
internal object MiniTcpCodec {
    const val IPV6_HEADER_BYTES = 40
    const val TCP_HEADER_BYTES = 20
    /** Smallest segment this stack cares about: IPv6 header + TCP header. */
    const val MIN_PACKET_BYTES = IPV6_HEADER_BYTES + TCP_HEADER_BYTES

    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10

    /** MSS we advertise and never exceed when sending, keeping frames inside one Ethernet MTU. */
    const val OUR_MSS = 1400

    /** One inbound TCP segment carved out of an IPv6 packet. */
    data class Segment(
        val sourcePort: Int,
        val destinationPort: Int,
        val sequence: Int,
        val acknowledgment: Int,
        val flags: Int,
        val window: Int,
        val maxSegmentSize: Int?,
        val payload: ByteArray,
        /** Total TCP segment length including header and options, for sequence accounting. */
        val segmentLength: Int,
    ) {
        val hasSyn: Boolean get() = flags and SYN != 0
        val hasAck: Boolean get() = flags and ACK != 0
        val hasFin: Boolean get() = flags and FIN != 0
        val hasRst: Boolean get() = flags and RST != 0
        /** Sequence-space length: payload plus one for SYN or FIN. */
        val seqSpace: Int get() = payload.size + (if (hasSyn || hasFin) 1 else 0)
    }

    /** Parses the TCP segment inside [ipv6]; null for truncated or extension-header packets. */
    fun parse(ipv6: ByteArray): Segment? {
        if (ipv6.size < MIN_PACKET_BYTES) return null
        if (ipv6[6].toInt() and 0xff != 6) return null // next header must be TCP
        val payloadLength = ((ipv6[4].toInt() and 0xff) shl 8) or (ipv6[5].toInt() and 0xff)
        if (ipv6.size < IPV6_HEADER_BYTES + payloadLength) return null
        val tcpStart = IPV6_HEADER_BYTES
        val tcpLength = payloadLength
        if (tcpLength < TCP_HEADER_BYTES) return null

        fun u8(at: Int): Int = ipv6[tcpStart + at].toInt() and 0xff
        fun u16(at: Int): Int = (u8(at) shl 8) or u8(at + 1)
        val dataOffsetBytes = (u8(12) shr 4) * 4 // high nibble, in 32-bit words → ×4
        if (dataOffsetBytes < TCP_HEADER_BYTES || dataOffsetBytes > tcpLength) return null

        var mss: Int? = null
        var optionAt = tcpStart + TCP_HEADER_BYTES
        val optionsEnd = tcpStart + dataOffsetBytes
        while (optionAt + 1 < optionsEnd) {
            when (u8(optionAt - tcpStart)) {
                0 -> break // end of options
                1 -> optionAt += 1 // no-op
                else -> {
                    val kind = u8(optionAt - tcpStart)
                    val len = u8(optionAt - tcpStart + 1)
                    if (len < 2 || optionAt + len > optionsEnd) return null
                    if (kind == 2 && len == 4) mss = u16(optionAt - tcpStart + 2)
                    optionAt += len
                }
            }
        }

        val payloadBytes = tcpLength - dataOffsetBytes
        val payload = ipv6.copyOfRange(tcpStart + dataOffsetBytes, tcpStart + tcpLength)
        return Segment(
            sourcePort = u16(0),
            destinationPort = u16(2),
            sequence = (u8(4) shl 24) or (u8(5) shl 16) or (u8(6) shl 8) or u8(7),
            acknowledgment = (u8(8) shl 24) or (u8(9) shl 16) or (u8(10) shl 8) or u8(11),
            flags = u8(13),
            window = u16(14),
            maxSegmentSize = mss,
            payload = payload,
            segmentLength = tcpLength,
        )
    }

    /** Builds one full IPv6 packet carrying a TCP segment with a valid checksum. */
    fun buildSegment(
        sourceIp: ByteArray,
        destinationIp: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        sequence: Int,
        acknowledgment: Int,
        flags: Int,
        window: Int,
        payload: ByteArray = ByteArray(0),
        advertiseMss: Int? = null,
    ): ByteArray {
        require(sourceIp.size == 16 && destinationIp.size == 16) { "IPv6 addresses must be 16 bytes" }
        val optionsBytes = if (advertiseMss != null) 4 else 0
        val tcpLength = TCP_HEADER_BYTES + optionsBytes + payload.size
        val packet = ByteArray(IPV6_HEADER_BYTES + tcpLength)

        // IPv6 header: version 6, traffic class/flow label zero.
        packet[0] = 0x60
        packet[4] = (tcpLength shr 8).toByte()
        packet[5] = tcpLength.toByte()
        packet[6] = 6 // next header: TCP
        packet[7] = 64 // hop limit
        sourceIp.copyInto(packet, 8)
        destinationIp.copyInto(packet, 24)

        // TCP header.
        packet[40] = (sourcePort shr 8).toByte()
        packet[41] = sourcePort.toByte()
        packet[42] = (destinationPort shr 8).toByte()
        packet[43] = destinationPort.toByte()
        writeInt(packet, 44, sequence)
        writeInt(packet, 48, acknowledgment)
        val dataOffsetWords = (TCP_HEADER_BYTES + optionsBytes) / 4
        packet[52] = ((dataOffsetWords shl 4) or ((flags shr 8) and 0x0f)).toByte()
        packet[53] = (flags and 0xff).toByte()
        packet[54] = (window shr 8).toByte()
        packet[55] = window.toByte()
        // Checksum at 56..57, urgent pointer zero at 58..59.
        if (advertiseMss != null) {
            packet[60] = 2 // MSS option kind
            packet[61] = 4 // option length
            packet[62] = (advertiseMss shr 8).toByte()
            packet[63] = advertiseMss.toByte()
        }
        payload.copyInto(packet, IPV6_HEADER_BYTES + TCP_HEADER_BYTES + optionsBytes)

        // Checksum over the IPv6 pseudo-header plus the whole TCP segment.
        var sum = 0L
        fun addBytes(from: Int, to: Int) {
            var pos = from
            while (pos + 1 < to) {
                sum += ((packet[pos].toInt() and 0xff) shl 8) or (packet[pos + 1].toInt() and 0xff)
                pos += 2
            }
            if (pos < to) sum += ((packet[pos].toInt() and 0xff) shl 8).toLong()
        }
        addBytes(8, 24) // pseudo-header source
        addBytes(24, 40) // pseudo-header destination
        sum += 6L // next header
        sum += tcpLength.toLong()
        addBytes(IPV6_HEADER_BYTES, packet.size)
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        val checksum = (sum.toInt().inv()) and 0xffff
        packet[56] = (checksum shr 8).toByte()
        packet[57] = checksum.toByte()
        return packet
    }

    /** Wraps an IPv6 packet into an Ethernet II frame (ether type 0x86dd). */
    fun wrapEthernet(sourceMac: ByteArray, destinationMac: ByteArray, ipv6: ByteArray): ByteArray {
        val frame = ByteArray(14 + ipv6.size)
        destinationMac.copyInto(frame, 0)
        sourceMac.copyInto(frame, 6)
        frame[12] = 0x86.toByte()
        frame[13] = -0x23 // 0xdd
        ipv6.copyInto(frame, 14)
        return frame
    }

    /** 32-bit sequence arithmetic: true when [a] >= [b] in wrap-around order. */
    fun seqGE(a: Int, b: Int): Boolean = a - b >= 0

    /** 32-bit sequence arithmetic: true when [a] > [b] in wrap-around order. */
    fun seqGT(a: Int, b: Int): Boolean = a - b > 0

    private fun writeInt(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 24).toByte()
        target[offset + 1] = (value ushr 16).toByte()
        target[offset + 2] = (value ushr 8).toByte()
        target[offset + 3] = value.toByte()
    }
}
