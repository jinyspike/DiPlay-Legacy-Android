package com.shilapi.xcertplay.network

import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.lang.Object
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * User-space TCP terminator for the wired AirPlay link (Route B for the T3 SYN black hole).
 *
 * On T3 head units the 4.4 kernel silently drops the iPhone's TCP SYN after it is injected into
 * the TUN: the packet reaches the TCP layer but never matches the listening socket, so no
 * SYN-ACK (and no RST) ever comes back and the iPhone gives up after 8 retransmits
 * (issues #133/#152/#163/#168). The kernel-side defect is out of the app's reach, so this stack
 * terminates TCP in-process instead: the NCM bridge hands it the raw IPv6 packet, it answers
 * SYN-ACK and manages the whole connection itself, and accepted byte streams are relayed over
 * loopback into the ordinary AirPlay [java.net.ServerSocket] — which keeps the entire
 * AirPlay/iAP2/MFi/media stack above untouched.
 *
 * Deliberately minimal, scoped to what CarPlay needs on this single-peer link:
 *  - listening side only; one accepted stream per inbound 4-tuple;
 *  - in-order receive with duplicate-ACK (out-of-order segments are dropped, the peer retransmits);
 *  - go-back-N retransmission with exponential backoff driven by a shared 150 ms scanner;
 *  - honest receive-window backpressure on both directions: the receive side advertises a
 *    zero-window when the relay lags, and the send side honors the peer's window including
 *    zero (RFC 1122 persist probes keep a reopened window from deadlocking the sender), with
 *    a bounded send queue that pauses the loopback reader instead of buffering without limit;
 *  - no window scaling (omitting WS in the SYN-ACK disables it per RFC 7323), no SACK, no timestamps.
 *
 * No Android imports: the stack is unit-testable on the JVM.
 */
class UserSpaceTcpStack(
    private val hostMac: ByteArray,
    /** 16 raw bytes of the wired TUN link-local address (e.g. fe80::2), scopeless. */
    private val hostLinkLocal: ByteArray,
    /** Loopback-side addresses the AirPlay listener is reachable at, tried in order. */
    private val relayCandidates: List<InetAddress>,
    /** Sends one Ethernet frame out the NCM link. Must be safe to call from any thread. */
    private val sendFrame: (ByteArray) -> Unit,
    private val log: (String) -> Unit = {},
) : Closeable {
    init {
        require(hostMac.size == 6) { "hostMac must be 6 bytes" }
        require(hostLinkLocal.size == 16) { "hostLinkLocal must be 16 bytes" }
    }

    private val running = AtomicBoolean(true)
    private val connections = ConcurrentHashMap<String, Connection>()
    private val isnCounter = AtomicInteger(0)
    private val retransmitExecutor = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "ustcp-retransmit").apply { isDaemon = true }
    }
    private val relayExecutor = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "ustcp-relay").apply { isDaemon = true }
    }

    val synReceived = AtomicInteger(0)
    val establishedCount = AtomicInteger(0)
    val relayConnected = AtomicInteger(0)
    val relayFailed = AtomicInteger(0)
    val retransmits = AtomicInteger(0)
    val resets = AtomicInteger(0)
    val bytesToPhone = AtomicLong(0)
    val bytesToCar = AtomicLong(0)

    init {
        retransmitExecutor.scheduleWithFixedDelay(
            { runCatching { pollRetransmits() } },
            RETRANSMIT_SCAN_PERIOD_MILLIS,
            RETRANSMIT_SCAN_PERIOD_MILLIS,
            TimeUnit.MILLISECONDS,
        )
    }

    /** One-line health summary for the diagnostic report. */
    fun summary(): String =
        "ustcp syn=$synReceived estab=$establishedCount relay=$relayConnected " +
            "relayFail=$relayFailed rtx=$retransmits rst=$resets " +
            "txToPhone=$bytesToPhone rxFromPhone=$bytesToCar conns=${connections.size}"

    /**
     * Handles one inbound IPv6 packet whose next header is TCP. Returns true when the packet was
     * consumed (the caller must then not inject it into the TUN), false when the packet does not
     * belong to this stack (not addressed to the wired link-local, malformed) and the legacy TUN
     * path should handle it.
     */
    fun onInboundPacket(ipv6: ByteArray, peerMac: ByteArray): Boolean {
        if (!running.get()) return false
        if (ipv6.size < MiniTcpCodec.MIN_PACKET_BYTES) return false
        if (!ipv6.contentEqualsRange(24, hostLinkLocal, 0, 16)) return false
        val segment = MiniTcpCodec.parse(ipv6) ?: return false
        val sourceIp = ipv6.copyOfRange(8, 24)
        val key = "${sourceIp.hostKey()}|${segment.sourcePort}|${segment.destinationPort}"

        val frames = ArrayList<ByteArray>(4)
        var owner = connections[key]
        if (owner != null && segment.hasSyn && !segment.hasAck && owner.isPastHandshake()) {
            // The phone reset and is re-connecting on the same 4-tuple: tear the stale
            // connection down so the bare SYN below is accepted as a fresh one instead of
            // poisoning the old connection's sequence space.
            owner.teardown()
            owner = null
        }
        if (owner == null) {
            if (segment.hasSyn && !segment.hasAck) {
                frames += acceptSyn(key, sourceIp, peerMac, segment)
                owner = connections[key]
            } else if (!segment.hasRst) {
                // Unknown mid-stream traffic: answer with RST so the peer gives up cleanly.
                frames += MiniTcpCodec.buildSegment(
                    sourceIp = hostLinkLocal, destinationIp = sourceIp,
                    sourcePort = segment.destinationPort, destinationPort = segment.sourcePort,
                    sequence = segment.acknowledgment, acknowledgment = segment.sequence + segment.seqSpace,
                    flags = MiniTcpCodec.RST or MiniTcpCodec.ACK, window = 0,
                )
            }
        } else {
            frames += owner.onSegment(segment)
        }
        val replyMac = owner?.peerMac ?: peerMac
        frames.forEach { frame ->
            runCatching { sendFrame(MiniTcpCodec.wrapEthernet(hostMac, replyMac, frame)) }
        }
        return true
    }

    /** Retransmission scan; runs on the shared executor and exposed for JVM tests. */
    internal fun pollRetransmits(nowNanos: Long = System.nanoTime()) {
        if (!running.get()) return
        for (connection in connections.values.toTypedArray()) {
            connection.retransmitScan(nowNanos)
        }
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        retransmitExecutor.shutdownNow()
        for (connection in connections.values.toTypedArray()) {
            connection.teardown()
        }
        relayExecutor.shutdownNow()
    }

    // ---------------------------------------------------------------- state machine

    private fun acceptSyn(
        key: String,
        sourceIp: ByteArray,
        peerMac: ByteArray,
        segment: MiniTcpCodec.Segment,
    ): ByteArray {
        // Count every SYN arrival, including ones answered with RST below — the diagnostic
        // report must show the phone's connection attempts even when the relay is down.
        synReceived.incrementAndGet()
        // Speculatively open the loopback relay now: a closed AirPlay port must be answered
        // with RST at SYN time (mirrors kernel behavior) instead of after the handshake.
        val localPort = key.substringAfterLast('|').toInt()
        var preConnected: Socket? = null
        for (candidate in relayCandidates) {
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(candidate, localPort), RELAY_CONNECT_TIMEOUT_MILLIS)
                preConnected = socket
                break
            } catch (error: IOException) {
                runCatching { socket.close() }
                log("ustcp relay probe failed at ${candidate.hostAddress}:$localPort: ${error.message}")
            }
        }
        if (preConnected == null) {
            relayFailed.incrementAndGet()
            resets.incrementAndGet()
            log("ustcp conn $key relay port closed on all candidates; RST at SYN time")
            return MiniTcpCodec.buildSegment(
                sourceIp = hostLinkLocal, destinationIp = sourceIp,
                sourcePort = segment.destinationPort, destinationPort = segment.sourcePort,
                sequence = segment.acknowledgment, acknowledgment = segment.sequence + segment.seqSpace,
                flags = MiniTcpCodec.RST or MiniTcpCodec.ACK, window = 0,
            )
        }
        val connection = Connection(key, sourceIp, peerMac, segment, preConnected)
        connections[key] = connection
        log("ustcp conn $key SYN received mss=${segment.maxSegmentSize} wnd=${segment.window}; replying SYN-ACK")
        return connection.buildAndQueue(
            flags = MiniTcpCodec.SYN,
            payload = ByteArray(0),
            advertiseMss = MiniTcpCodec.OUR_MSS,
        )
    }

    private inner class Connection(
        val key: String,
        val remoteIp: ByteArray,
        initialPeerMac: ByteArray,
        syn: MiniTcpCodec.Segment,
        preConnectedSocket: Socket?,
    ) {
        private val lock: Object = Object()
        private val localPort: Int = key.substringAfterLast('|').toInt()
        private val remotePort: Int = key.split('|').getOrNull(1)?.toInt() ?: 0
        @Volatile var peerMac: ByteArray = initialPeerMac
        var state = STATE_SYN_RECEIVED
        private val iss: Int = System.nanoTime().toInt() + isnCounter.addAndGet(63_721)
        private var sndUna: Int = iss
        private var sndNxt: Int = iss
        private var rcvNxt: Int = syn.sequence + 1
        private var sndWnd: Int = if (syn.window > 0) syn.window else 4096
        private var peerMss: Int = (syn.maxSegmentSize ?: MiniTcpCodec.OUR_MSS).coerceAtMost(MiniTcpCodec.OUR_MSS)
        private var rtoNanos = INITIAL_RTO_NANOS
        private val retransmitQueue = ArrayDeque<OutboundSegment>()
        private val deliverQueue = LinkedBlockingQueue<ByteArray>()
        private var undeliveredBytes = 0
        private var loopbackEof = false
        private var peerClosed = false
        private var finSent = false
        @Volatile private var closedByStack = false
        private var relaySocket: Socket? = null
        private var preConnected: Socket? = preConnectedSocket
        private val outData = ArrayDeque<ByteArray>()
        /** Total bytes queued in [outData]; bounded via [OUT_DATA_MAX_BYTES] backpressure. */
        private var outDataBytes = 0

        /** True once the handshake completed (used to detect same-4-tuple reconnects). */
        fun isPastHandshake(): Boolean = synchronized(lock) { state != STATE_SYN_RECEIVED }

        fun onSegment(segment: MiniTcpCodec.Segment): List<ByteArray> {
            val frames = ArrayList<ByteArray>(4)
            var wakeSender = false
            synchronized(lock) {
                if (closedByStack) return frames
                if (segment.hasRst) {
                    // Accepted without a sequence-window check (RFC 793 requires one): the
                    // USB NCM link is point-to-point, so blind RST injection is not a threat.
                    resets.incrementAndGet()
                    log("ustcp conn $key RST received; tearing down")
                    teardownLocked()
                    return frames
                }
                // ACK processing: advance sndUna, drop fully-acked retransmit segments, refresh window.
                if (segment.hasAck) {
                    val ack = segment.acknowledgment
                    if (MiniTcpCodec.seqGT(ack, sndUna) && !MiniTcpCodec.seqGT(ack, sndNxt)) {
                        sndUna = ack
                        rtoNanos = INITIAL_RTO_NANOS
                        val iterator = retransmitQueue.iterator()
                        while (iterator.hasNext()) {
                            val queued = iterator.next()
                            if (MiniTcpCodec.seqGE(ack, queued.seq + queued.seqSpace)) iterator.remove()
                        }
                        wakeSender = outData.isNotEmpty()
                    }
                    if (state == STATE_SYN_RECEIVED && MiniTcpCodec.seqGE(ack, iss + 1)) {
                        state = STATE_ESTABLISHED
                        establishedCount.incrementAndGet()
                        log("ustcp conn $key handshake complete (ESTABLISHED); connecting relay")
                        startRelay()
                    }
                    if (segment.window != sndWnd) {
                        sndWnd = segment.window
                        // A window update — including a close-to-zero one — must reach the
                        // sender even when the ACK does not advance sndUna, otherwise a
                        // reopened window would never drain outData.
                        if (outData.isNotEmpty()) wakeSender = true
                    }
                }

                when (state) {
                    STATE_SYN_RECEIVED -> {
                        // Peer retransmitted the SYN (our SYN-ACK may have been lost): resend it.
                        if (segment.hasSyn && !segment.hasAck) {
                            frames += buildAndQueue(
                                flags = MiniTcpCodec.SYN,
                                payload = ByteArray(0),
                                advertiseMss = MiniTcpCodec.OUR_MSS,
                            )
                        }
                    }
                    else -> {
                        handleData(segment, frames)
                        // Once our FIN is fully acked the connection is done (LAST_ACK settle).
                        if (finSent && retransmitQueue.isEmpty()) finishLocked()
                    }
                }
            }
            if (wakeSender) senderPass()
            return frames
        }

        /** Data/FIN receive path; caller holds [lock]. */
        private fun handleData(segment: MiniTcpCodec.Segment, frames: MutableList<ByteArray>) {
            val payloadLength = segment.payload.size
            if (payloadLength == 0 && !segment.hasFin) {
                // Pure ACK: ACK processing above already ran. Per RFC 793 a pure ACK is not
                // answered with another ACK.
                return
            }
            val isKeepalive = payloadLength == 1 && segment.sequence == rcvNxt - 1 && !segment.hasFin
            val windowAvailable = RECV_WINDOW_BYTES - undeliveredBytes
            when {
                isKeepalive -> frames += buildAck()
                segment.sequence == rcvNxt &&
                    windowAvailable >= (payloadLength + if (segment.hasFin) 1 else 0) -> {
                    rcvNxt = segment.sequence + segment.seqSpace
                    if (payloadLength > 0) {
                        deliverQueue.add(segment.payload)
                        undeliveredBytes += payloadLength
                        bytesToCar.addAndGet(payloadLength.toLong())
                    }
                    if (segment.hasFin) {
                        peerClosed = true
                        if (state == STATE_ESTABLISHED) state = STATE_CLOSE_WAIT
                        log("ustcp conn $key FIN from phone; rcvNxt=$rcvNxt")
                    }
                    frames += buildAck()
                }
                else -> frames += buildAck() // old, out-of-order or zero-window: duplicate-ACK
            }
        }

        /** Caller holds [lock]. Builds an ACK for the current receive state. */
        private fun buildAck(): ByteArray = MiniTcpCodec.buildSegment(
            sourceIp = hostLinkLocal, destinationIp = remoteIp,
            sourcePort = localPort, destinationPort = remotePort,
            sequence = sndNxt, acknowledgment = rcvNxt,
            flags = MiniTcpCodec.ACK, window = (RECV_WINDOW_BYTES - undeliveredBytes).coerceAtLeast(0),
        )

        /** Builds one segment, queues it for retransmission, and returns the raw IPv6 packet. */
        internal fun buildAndQueue(
            flags: Int,
            payload: ByteArray,
            advertiseMss: Int? = null,
        ): ByteArray {
            val seq = sndNxt
            val packet = MiniTcpCodec.buildSegment(
                sourceIp = hostLinkLocal, destinationIp = remoteIp,
                sourcePort = localPort, destinationPort = remotePort,
                sequence = seq, acknowledgment = rcvNxt,
                flags = flags or MiniTcpCodec.ACK, window = (RECV_WINDOW_BYTES - undeliveredBytes).coerceAtLeast(0),
                payload = payload, advertiseMss = advertiseMss,
            )
            val seqSpace = payload.size + (if (flags and (MiniTcpCodec.SYN or MiniTcpCodec.FIN) != 0) 1 else 0)
            val queued = OutboundSegment(
                packet = packet,
                seq = seq, seqSpace = seqSpace,
            )
            retransmitQueue.addLast(queued)
            sndNxt += seqSpace
            return packet
        }

        fun retransmitScan(nowNanos: Long) {
            val frames = ArrayList<ByteArray>(8)
            var giveUp = false
            synchronized(lock) {
                if (closedByStack || retransmitQueue.isEmpty()) return
                val head = retransmitQueue.first()
                if (nowNanos - head.sentAtNanos < rtoNanos) return
                if (head.attempts >= MAX_RETRANSMIT_ATTEMPTS) {
                    log("ustcp conn $key peer unresponsive after $MAX_RETRANSMIT_ATTEMPTS retransmits; giving up")
                    giveUp = true
                } else {
                    rtoNanos = (rtoNanos shl 1).coerceAtMost(MAX_RTO_NANOS)
                    for (queued in retransmitQueue) {
                        queued.attempts += 1
                        queued.sentAtNanos = nowNanos
                        frames.add(queued.packet)
                    }
                    retransmits.addAndGet(frames.size)
                }
            }
            if (giveUp) {
                teardown()
                return
            }
            frames.forEach { frame ->
                val ethernet = synchronized(lock) { MiniTcpCodec.wrapEthernet(hostMac, peerMac, frame) }
                runCatching { sendFrame(ethernet) }
            }
        }

        /** Caller holds [lock]. */
        private fun teardownLocked() {
            closedByStack = true
            runCatching { relaySocket?.close() }
            runCatching { preConnected?.close() }
            connections.remove(key)
            lock.notifyAll()
        }

        fun teardown() {
            synchronized(lock) {
                if (!closedByStack) {
                    log("ustcp conn $key teardown")
                    teardownLocked()
                }
            }
        }

        private fun finishLocked() {
            log("ustcp conn $key closed cleanly (ustcp stats: ${summary()})")
            teardownLocked()
        }

        private fun startRelay() {
            relayExecutor.execute {
                var connected: Socket? = synchronized(lock) { preConnected.also { preConnected = null } }
                if (connected == null) {
                    for (candidate in relayCandidates) {
                        val socket = Socket()
                        try {
                            socket.tcpNoDelay = true
                            socket.connect(InetSocketAddress(candidate, localPort), RELAY_CONNECT_TIMEOUT_MILLIS)
                            connected = socket
                            break
                        } catch (error: IOException) {
                            runCatching { socket.close() }
                            log("ustcp relay connect failed at ${candidate.hostAddress}:$localPort: ${error.message}")
                        }
                    }
                }
                val relay = connected
                if (relay == null) {
                    relayFailed.incrementAndGet()
                    log("ustcp conn $key relay connect failed on all candidates; sending RST")
                    // Read seq/ack under the lock: they are plain fields touched by other threads.
                    val rstPacket = synchronized(lock) {
                        MiniTcpCodec.buildSegment(
                            sourceIp = hostLinkLocal, destinationIp = remoteIp,
                            sourcePort = localPort, destinationPort = remotePort,
                            sequence = sndNxt, acknowledgment = rcvNxt,
                            flags = MiniTcpCodec.RST or MiniTcpCodec.ACK, window = 0,
                        )
                    }
                    runCatching { sendFrame(MiniTcpCodec.wrapEthernet(hostMac, peerMac, rstPacket)) }
                    teardown()
                    return@execute
                }
                synchronized(lock) {
                    if (closedByStack) {
                        runCatching { relay.close() }
                        return@execute
                    }
                    relaySocket = relay
                }
                relayConnected.incrementAndGet()
                log("ustcp conn $key relay connected to ${relay.remoteSocketAddress}")
                Thread({ deliverToLoopback(relay) }, "ustcp-to-loopback-$key").apply {
                    isDaemon = true
                    start()
                }
                Thread({ readFromLoopback(relay) }, "ustcp-from-loopback-$key").apply {
                    isDaemon = true
                    start()
                }
            }
        }

        /** Stack → loopback: drains received payload into the relayed socket. */
        private fun deliverToLoopback(socket: Socket) {
            try {
                val output: OutputStream = socket.getOutputStream()
                while (running.get() && !closedByStack) {
                    val chunk = deliverQueue.poll(500, TimeUnit.MILLISECONDS) ?: continue
                    output.write(chunk)
                    output.flush()
                    synchronized(lock) {
                        undeliveredBytes -= chunk.size
                        lock.notifyAll()
                    }
                }
            } catch (_: InterruptedException) {
            } catch (error: IOException) {
                if (running.get()) {
                    log("ustcp conn $key relay write failed: ${error.message}")
                    teardown()
                }
            }
        }

        /** Loopback → stack: chops the AirPlay reply stream into MSS-sized send chunks. */
        private fun readFromLoopback(socket: Socket) {
            val buffer = ByteArray(MiniTcpCodec.OUR_MSS)
            try {
                val input: InputStream = socket.getInputStream()
                while (running.get() && !closedByStack) {
                    // Send-side backpressure: stop draining loopback while the outbound queue
                    // is full (peer window closed or slow), so memory stays bounded. A drained
                    // queue (senderPass) or teardown wakes this wait.
                    synchronized(lock) {
                        while (outDataBytes >= OUT_DATA_MAX_BYTES && running.get() && !closedByStack) {
                            lock.wait(200)
                        }
                        if (!running.get() || closedByStack) return
                    }
                    val read = input.read(buffer)
                    if (read == -1) {
                        synchronized(lock) {
                            loopbackEof = true
                            lock.notifyAll()
                        }
                        senderPass()
                        return
                    }
                    val chunk = buffer.copyOf(read)
                    synchronized(lock) {
                        outData.addLast(chunk)
                        outDataBytes += read
                        lock.notifyAll()
                    }
                    senderPass()
                }
            } catch (error: IOException) {
                if (running.get() && !closedByStack) {
                    log("ustcp conn $key relay read failed: ${error.message}")
                    teardown()
                }
            }
        }

        /** Sends queued loopback data (and eventually FIN) while the peer's window allows. */
        private fun senderPass() {
            val frames = ArrayList<ByteArray>(4)
            synchronized(lock) {
                if (closedByStack || state == STATE_SYN_RECEIVED) return
                while (outData.isNotEmpty()) {
                    val windowAvailable = sndWnd - (sndNxt - sndUna)
                    if (windowAvailable <= 0) break
                    val head = outData.first()
                    val length = minOf(head.size, peerMss, windowAvailable)
                    outData.removeFirst()
                    outDataBytes -= length
                    if (length < head.size) outData.addFirst(head.copyOfRange(length, head.size))
                    frames.add(
                        buildAndQueue(
                            flags = MiniTcpCodec.ACK or MiniTcpCodec.PSH,
                            payload = head.copyOf(length),
                        ),
                    )
                    bytesToPhone.addAndGet(length.toLong())
                }
                // Zero-window probe (RFC 1122 persist timer): when data is pending but the
                // peer's window is closed and nothing is unacked, push the first pending byte
                // out at sndNxt. A peer with a still-zero window discards the byte but the
                // segment stays in the retransmit queue, so the scanner keeps resending it
                // (with backoff) until the window reopens and the byte is finally accepted.
                if (outData.isNotEmpty() && retransmitQueue.isEmpty()) {
                    val windowAvailable = sndWnd - (sndNxt - sndUna)
                    if (windowAvailable <= 0) {
                        val head = outData.removeFirst()
                        frames.add(
                            buildAndQueue(
                                flags = MiniTcpCodec.ACK or MiniTcpCodec.PSH,
                                payload = byteArrayOf(head[0]),
                            ),
                        )
                        // Only the first byte goes out as the probe; the rest of the chunk
                        // must stay queued or it would be silently dropped.
                        if (head.size > 1) outData.addFirst(head.copyOfRange(1, head.size))
                        outDataBytes -= 1
                        bytesToPhone.incrementAndGet()
                        log("ustcp conn $key zero-window probe sent (1 byte, sndWnd=$sndWnd)")
                    }
                }
                if (outData.isEmpty() && loopbackEof && !finSent) {
                    finSent = true
                    state = STATE_FIN_WAIT
                    frames.add(buildAndQueue(flags = MiniTcpCodec.FIN, payload = ByteArray(0)))
                    log("ustcp conn $key FIN sent")
                }
                lock.notifyAll()
            }
            frames.forEach { frame ->
                runCatching { sendFrame(MiniTcpCodec.wrapEthernet(hostMac, peerMac, frame)) }
            }
        }
    }

    private inner class OutboundSegment(
        val packet: ByteArray,
        val seq: Int,
        val seqSpace: Int,
        @Volatile var sentAtNanos: Long = System.nanoTime(),
        @Volatile var attempts: Int = 0,
    )

    private companion object {
        const val STATE_SYN_RECEIVED = 1
        const val STATE_ESTABLISHED = 2
        const val STATE_CLOSE_WAIT = 3
        const val STATE_FIN_WAIT = 4
        const val INITIAL_RTO_NANOS = 300_000_000L
        const val MAX_RTO_NANOS = 3_000_000_000L
        const val MAX_RETRANSMIT_ATTEMPTS = 8
        const val RECV_WINDOW_BYTES = 65_535
        // Loopback connects are instant successes or immediate connection-refused failures;
        // the timeout only covers pathological cases. Keep it short: acceptSyn probes run on
        // the NCM read thread, so every blocked millisecond delays all inbound frames.
        const val RELAY_CONNECT_TIMEOUT_MILLIS = 200
        const val RETRANSMIT_SCAN_PERIOD_MILLIS = 150L
        /** Send-queue cap for loopback backpressure (~2× the maximum receive window). */
        const val OUT_DATA_MAX_BYTES = 128 * 1024
    }
}

private fun ByteArray.contentEqualsRange(sourceOffset: Int, other: ByteArray, otherOffset: Int, length: Int): Boolean {
    if (sourceOffset + length > size || otherOffset + length > other.size) return false
    for (index in 0 until length) {
        if (this[sourceOffset + index] != other[otherOffset + index]) return false
    }
    return true
}

private fun ByteArray.hostKey(): String = joinToString(":") { byte -> "%02x".format(byte.toInt() and 0xff) }
