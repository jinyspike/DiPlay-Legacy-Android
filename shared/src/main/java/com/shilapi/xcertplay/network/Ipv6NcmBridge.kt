package com.shilapi.xcertplay.network

import android.os.ParcelFileDescriptor
import android.util.Log
import com.shilapi.xcertplay.transport.EthernetIpv6Codec
import com.shilapi.xcertplay.transport.NcmUsbBridge
import java.io.Closeable
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.LockSupport

/**
 * Moves IPv6 packets between an Android VpnService tun and the iPhone NCM Ethernet link.
 *
 * NCM carries Ethernet frames while the tun is a layer-3 device, so this bridge strips and
 * restores the Ethernet II header. Link-local neighbor discovery stays in the Android kernel,
 * mirroring LIVI's reliance on the host kernel for NDP on its TAP interface.
 */
class Ipv6NcmBridge(
    private val ncm: NcmUsbBridge,
    private val tun: ParcelFileDescriptor,
    private val hostMac: ByteArray,
    /** Link-local IPv6 address assigned to the Android TUN side (e.g. "fe80::2"). */
    private val hostLinkLocal: String,
    private val onDebugLog: (String) -> Unit = {},
    private val onError: (Throwable) -> Unit,
    /**
     * Issue #148: answers the iPhone's wired mDNS queries for _airplay._tcp with unicast
     * responses. JmDNS multicast announcements cannot cross the VPN TUN (the kernel
     * routes multicast out the physical interface), so without this the iPhone keeps
     * querying and never opens TCP/7000. Null disables the interception.
     */
    @Volatile var mdnsResponder: WiredMdnsResponder? = null,
    /**
     * User-space TCP terminator (T3 wired kernel bypass). When attached, TCP segments addressed
     * to the wired link-local are answered and relayed in-process; the 4.4 kernel never sees
     * them (issues #133/#152/#168: the kernel silently drops the iPhone's SYN). Null keeps the
     * legacy TUN path.
     */
    @Volatile var userSpaceTcp: UserSpaceTcpStack? = null,
) : Closeable {
    init {
        require(hostMac.size == EthernetIpv6Codec.MAC_BYTES) { "hostMac must be 6 bytes" }
    }

    @Volatile
    private var peerMac: ByteArray? = null
    private val hostLinkLocalBytes = InetAddress.getByName(hostLinkLocal).address
    private val allNodesIpv6 = byteArrayOf(
        0xff.toByte(), 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    )
    private val allNodesMac = byteArrayOf(0x33, 0x33, 0, 0, 0, 0x01)
    private var loggedInbound = false
    private var loggedOutbound = false
    private var loggedWaitingForPeer = false
    private var inboundLogBudget = 16
    /**
     * Issue #95: the report never shows whether the iPhone sends TCP SYN to port 7000 —
     * the L4 summary only reaches logcat. Mirror a redacted per-packet summary into the
     * diagnostic report (separate small budget) so the next report can distinguish
     * "iPhone never sent TCP" from "SYN lost in bridge/TUN/kernel".
     */
    private var reportInboundBudget = 8
    /**
     * Issue #131: the pre-StartSession mDNS/ICMPv6 chatter eats the whole #95 report
     * budget, so a TCP SYN arriving later never reaches the exported report and "iPhone
     * never sent SYN" stays indistinguishable from "SYN lost in bridge/TUN/kernel".
     * TCP packets draw from this reserved budget first, keeping SYN visibility.
     */
    private var reportTcpBudget = 8
    private var outboundLogBudget = 24
    /** Issue #148: keep wired mDNS answers visible without spamming the report. */
    private var mdnsAnswerLogBudget = 6
    /** Issue #152: keep unmatched wired mDNS query names visible without spamming. */
    private var unmatchedMdnsLogBudget = 6
    /**
     * Issue #155/#123: the iPhone's TCP SYNs reach the NCM bridge but the kernel never
     * answers on some 4.4 kernels. Count TCP packets written into the TUN so a later
     * report can tell "bridge never wrote" from "kernel dropped / never answered".
     */
    val injectedTcpPackets = AtomicInteger(0)
    /** Issue #123: confirm each sampled SYN actually made it into the TUN. */
    private var tunInjectLogBudget = 8
    @Volatile
    private var lastNaTimeNanos = 0L
    private val ustcpHandledLogged = AtomicBoolean(false)
    private val running = AtomicBoolean(false)
    private lateinit var ncmToTunThread: Thread
    private lateinit var tunToNcmThread: Thread

    fun start() {
        check(running.compareAndSet(false, true)) { "bridge is already started" }
        // Send an unsolicited Neighbor Advertisement (to all-nodes ff02::1) so the iPhone can
        // learn our MAC without completing a Solicitation → Advertisement round-trip first.
        // Without this, our unicast NA reply is silently dropped while peerMac is still null,
        // causing a deadlock: iPhone never learns fe80::2's MAC, never connects AirPlay TCP,
        // and the USB read queue times out with "FAILED: Android could not queue USBMUX read request".
        sendUnsolicitedNeighborAdvertisement(force = true)
        ncmToTunThread = Thread(::runNcmToTun, "ncm-ipv6-in").apply {
            isDaemon = true
            start()
        }
        tunToNcmThread = Thread(::runTunToNcm, "ncm-ipv6-out").apply {
            isDaemon = true
            start()
        }
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        ncm.close()
        // Issue #168: do NOT close the TUN here. Its lifecycle belongs to
        // CarPlayVpnService, which deliberately keeps it open across wired
        // attempts (reuseTun skips establish() to avoid leaking the 4.4 netd
        // UID fwmark rule). Closing it here makes every retry die with
        // "Already closed" at the next attach(). The TUN is closed in
        // CarPlayVpnService.onDestroy().
        join(ncmToTunThread)
        join(tunToNcmThread)
        userSpaceTcp?.close()
    }

    private fun runNcmToTun() {
        val output = FileOutputStream(tun.fileDescriptor)
        try {
            while (running.get()) {
                val frame = ncm.recv(READ_TIMEOUT_MILLIS)
                if (frame == null) {
                    if (peerMac == null) {
                        sendUnsolicitedNeighborAdvertisement()
                    }
                    continue
                }
                val ipv6 = EthernetIpv6Codec.parseIpv6View(frame) ?: continue
                peerMac = ipv6.sourceMac

                if (EthernetIpv6Codec.isNeighborSolicitationFor(frame, ipv6.payloadOffset, ipv6.payloadLength, hostLinkLocalBytes)) {
                    val peerIp = frame.copyOfRange(ipv6.payloadOffset + 8, ipv6.payloadOffset + 24)
                    val isUnspecified = peerIp.all { it == 0.toByte() }
                    val replyDstMac = if (isUnspecified) allNodesMac else ipv6.sourceMac
                    val replyDstIp = if (isUnspecified) allNodesIpv6 else peerIp
                    val naFrame = EthernetIpv6Codec.buildNeighborAdvertisement(
                        hostMac = hostMac,
                        peerMac = replyDstMac,
                        hostIpv6 = hostLinkLocalBytes,
                        peerIpv6 = replyDstIp,
                        solicited = !isUnspecified,
                    )
                    ncm.send(naFrame, WRITE_TIMEOUT_MILLIS)
                    val naMsg = "ncm replied with solicited neighbor advertisement to peer ${ipv6.sourceMac.macString()}"
                    Log.i(TAG, naMsg)
                    runCatching { onDebugLog(naMsg) }
                    // This bridge owns NDP for hostLinkLocal. A TUN has no Ethernet
                    // neighbour entry: forwarding an already-answered NS into Android's
                    // layer-3 stack can trigger a second (or malformed) NA.
                    // Keep all other IPv6 packets on the ordinary TUN path.
                    continue
                }

                // Issue #148: answer the iPhone's mDNS queries for the wired AirPlay
                // service with a unicast response sent straight back over NCM. The
                // query must not also be injected into the TUN: nothing on the TUN
                // answers it usefully, and a duplicate multicast reply would only
                // confuse the iPhone's resolver.
                val responder = mdnsResponder
                val mdnsAnswers = responder?.answerFrames(
                    frame, ipv6.payloadOffset, ipv6.payloadLength, hostMac, ipv6.sourceMac,
                ) ?: emptyList()
                if (mdnsAnswers.isNotEmpty()) {
                    // Issue #163: a non-QU query also gets a multicast copy, so the
                    // iPhone sees the answer even if it ignores unicast replies.
                    for (mdnsAnswer in mdnsAnswers) {
                        ncm.send(mdnsAnswer, WRITE_TIMEOUT_MILLIS)
                    }
                    if (mdnsAnswerLogBudget > 0) {
                        mdnsAnswerLogBudget--
                        val answerMsg = "WIRED-CHAIN [15/16] mDNS _airplay query answered frames=${mdnsAnswers.size} " +
                            "bytes=${mdnsAnswers.sumOf { it.size }}"
                        Log.i(TAG, answerMsg)
                        runCatching { onDebugLog(answerMsg) }
                    }
                    continue
                }
                // Issue #152: when no answer matched, record what the iPhone actually
                // asked for so the next report shows the real query names.
                if (responder != null && unmatchedMdnsLogBudget > 0) {
                    val queryName = responder.unmatchedQueryName(frame, ipv6.payloadOffset, ipv6.payloadLength)
                    if (queryName != null) {
                        unmatchedMdnsLogBudget--
                        runCatching { onDebugLog("ncm wired mdns query not answered name=$queryName") }
                    }
                }

                if (!loggedInbound) {
                    loggedInbound = true
                    val inMsg = "ncm first inbound ipv6 bytes=${ipv6.payloadLength} peer=${ipv6.sourceMac.macString()}"
                    Log.i(TAG, inMsg)
                    runCatching { onDebugLog(inMsg) }
                    sendUnsolicitedNeighborAdvertisement(force = true, targetMac = ipv6.sourceMac)
                }
                if (inboundLogBudget > 0) {
                    inboundLogBudget--
                    Log.i(TAG, "ncm inbound ${frame.summary(ipv6.payloadOffset)}")
                }
                val inboundNextHeader =
                    if (ipv6.payloadLength >= 40) (frame[ipv6.payloadOffset + 6].toInt() and 0xff) else -1
                if (inboundNextHeader == 6 && reportTcpBudget > 0) {
                    // Issue #131: TCP packets draw from the reserved budget so a SYN
                    // arriving after StartSession stays visible in the exported report.
                    reportTcpBudget--
                    runCatching { onDebugLog("ncm inbound diag ${frame.diagnosticSummary(ipv6.payloadOffset)}") }
                } else if (reportInboundBudget > 0) {
                    reportInboundBudget--
                    runCatching { onDebugLog("ncm inbound diag ${frame.diagnosticSummary(ipv6.payloadOffset)}") }
                }
                val isTcp = inboundNextHeader == 6
                // User-space TCP: terminate in-process and relay to the AirPlay listener over
                // loopback instead of injecting into the kernel (T3 SYN black hole bypass).
                val stack = userSpaceTcp
                if (isTcp && stack != null && stack.onInboundPacket(
                        frame.copyOfRange(ipv6.payloadOffset, ipv6.payloadOffset + ipv6.payloadLength),
                        ipv6.sourceMac,
                    )
                ) {
                    if (ustcpHandledLogged.compareAndSet(false, true)) {
                        val msg = "WIRED-CHAIN [16/16] TCP handled by user-space stack (kernel bypass)"
                        Log.i(TAG, msg)
                        runCatching { onDebugLog(msg) }
                    }
                    continue
                }
                if (isTcp) {
                    // Counts only packets that actually cross into the kernel TUN (packets the
                    // user-space stack consumed are skipped above, keeping the diagnostic honest).
                    val tcpCount = injectedTcpPackets.incrementAndGet()
                    if (tcpCount == 1) {
                        val tcpMsg = "WIRED-CHAIN [16/16] first inbound TCP packet injected to TUN"
                        Log.i(TAG, tcpMsg)
                        runCatching { onDebugLog(tcpMsg) }
                    }
                }
                output.write(frame, ipv6.payloadOffset, ipv6.payloadLength)
                if (isTcp && tunInjectLogBudget > 0) {
                    // Issue #123: prove the SYN crossed into the kernel's TUN. A throw
                    // above surfaces through onError instead; reaching here means the
                    // write completed.
                    tunInjectLogBudget--
                    val dstPort = if (ipv6.payloadLength >= 44) {
                        ((frame[ipv6.payloadOffset + 42].toInt() and 0xff) shl 8) or
                            (frame[ipv6.payloadOffset + 43].toInt() and 0xff)
                    } else -1
                    // Issue #155/#160: a SYN whose destination is not the TUN address,
                    // or whose TCP checksum is bad, is dropped by the kernel silently
                    // (no SYN_RECV, no RST) — exactly the observed signature. Record
                    // both so the next report can rule them in or out.
                    val dstLocal = ipv6.payloadLength >= 40 &&
                        frame.copyOfRange(
                            ipv6.payloadOffset + 24,
                            ipv6.payloadOffset + 40,
                        ).contentEquals(hostLinkLocalBytes)
                    val checksumOk = tcpChecksumValid(frame, ipv6.payloadOffset, ipv6.payloadLength)
                    runCatching {
                        onDebugLog(
                            "ncm tun inject tcp bytes=${ipv6.payloadLength} dstPort=$dstPort " +
                                "dstLocal=$dstLocal tcpChecksum=${if (checksumOk) "ok" else "bad"} ok",
                        )
                    }
                }
            }
        } catch (error: IOException) {
            if (running.get()) onError(error)
        } catch (error: RuntimeException) {
            if (running.get()) onError(error)
        }
    }

    private fun runTunToNcm() {
        val input = FileInputStream(tun.fileDescriptor)
        val buffer = ByteArray(TUN_READ_BYTES)
        try {
            while (running.get()) {
                val length = input.read(buffer)
                if (length == -1) {
                    if (running.get()) onError(IOException("NCM IPv6 tunnel closed"))
                    return
                }
                // Android's TUN fd may transiently report a zero-byte read while its network is
                // being registered. It is neither EOF (-1) nor an IPv6 packet.
                if (length == 0) {
                    LockSupport.parkNanos(ZERO_READ_BACKOFF_NANOS)
                    continue
                }
                val tunPacket = buffer.copyOf(length)
                val ipv6 = EthernetIpv6Codec.addNeighborAdvertisementTargetMac(tunPacket, hostMac)
                if (ipv6.size != tunPacket.size) {
                    Log.i(TAG, "ncm added target-link-layer option to neighbor advertisement")
                }
                if (outboundLogBudget > 0) {
                    outboundLogBudget--
                    Log.i(TAG, "ncm outbound ${ipv6.summary(0)}")
                }
                val multicastMac = EthernetIpv6Codec.multicastDestinationMac(ipv6)
                val mac = multicastMac ?: peerMac
                if (mac == null) {
                    sendUnsolicitedNeighborAdvertisement()
                    if (!loggedWaitingForPeer) {
                        loggedWaitingForPeer = true
                        Log.i(TAG, "ncm deferred outbound unicast bytes=$length until peer MAC is learned")
                    }
                    continue
                }
                if (!loggedOutbound) {
                    loggedOutbound = true
                    val outMsg = "ncm first outbound ipv6 bytes=$length destination=${mac.macString()} multicast=${multicastMac != null}"
                    Log.i(TAG, outMsg)
                    runCatching { onDebugLog(outMsg) }
                }
                val frame = EthernetIpv6Codec.build(hostMac, mac, ipv6)
                ncm.send(frame, WRITE_TIMEOUT_MILLIS)
            }
        } catch (error: IOException) {
            if (running.get()) onError(error)
        } catch (error: RuntimeException) {
            if (running.get()) onError(error)
        }
    }

    /**
     * Sends an unsolicited Neighbor Advertisement for [hostLinkLocal] to the all-nodes multicast
     * group (ff02::1), with Override=1 and Source Link-Layer Address option, so the iPhone can
     * cache our MAC immediately without a Neighbor Solicitation round-trip.
     *
     * ICMPv6 NA wire format (RFC 4861 §4.4):
     *   IPv6 header (40 bytes)
     *   ICMPv6 type=136, code=0, checksum (4 bytes)
     *   flags R|S|O (4 bytes, bits 31-29)  — we set Override (bit 29)
     *   Target address (16 bytes)
     *   Option: Target Link-Layer Address (type=2, len=1, MAC: 6 bytes → 8 bytes total)
     */
    fun sendUnsolicitedNeighborAdvertisement(force: Boolean = false, targetMac: ByteArray? = null) {
        if (!running.get()) return
        val now = System.nanoTime()
        synchronized(this) {
            if (!force && now - lastNaTimeNanos < NA_RETRY_INTERVAL_NANOS) return
            lastNaTimeNanos = now
        }
        try {
            val dstMac = targetMac ?: peerMac ?: allNodesMac
            val frame = EthernetIpv6Codec.buildNeighborAdvertisement(
                hostMac = hostMac,
                peerMac = dstMac,
                hostIpv6 = hostLinkLocalBytes,
                peerIpv6 = allNodesIpv6,
                solicited = false,
            )
            ncm.send(frame, WRITE_TIMEOUT_MILLIS)
            val naMsg = "ncm sent unsolicited neighbor advertisement for $hostLinkLocal"
            Log.i(TAG, naMsg)
            runCatching { onDebugLog(naMsg) }
        } catch (error: Exception) {
            Log.w(TAG, "ncm unsolicited NA send failed: ${error.message}")
        }
    }

    private fun join(thread: Thread) {
        if (thread === Thread.currentThread()) return
        try {
            thread.join(JOIN_TIMEOUT_MILLIS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        if (thread.isAlive) thread.interrupt()
    }

    private fun ByteArray.macString(): String =
        joinToString(":") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun ByteArray.summary(offset: Int): String {
        val payloadBytes = size - offset
        if (payloadBytes < 40) return "truncated bytes=$payloadBytes"
        val source = InetAddress.getByAddress(copyOfRange(offset + 8, offset + 24)).hostAddress
        val destination = InetAddress.getByAddress(copyOfRange(offset + 24, offset + 40)).hostAddress
        val nextHeader = this[offset + 6].toInt() and 0xff
        val detail = when {
            nextHeader == 6 && payloadBytes >= 44 -> " tcp=${u16(offset + 40)}->${u16(offset + 42)}"
            nextHeader == 17 && payloadBytes >= 44 -> " udp=${u16(offset + 40)}->${u16(offset + 42)}"
            nextHeader == 58 && payloadBytes >= 41 -> " icmp6=${this[offset + 40].toInt() and 0xff}"
            else -> ""
        }
        return "bytes=$payloadBytes src=$source dst=$destination next=$nextHeader$detail"
    }

    private fun ByteArray.u16(offset: Int): Int =
        ((this[offset].toInt() and 0xff) shl 8) or (this[offset + 1].toInt() and 0xff)

    /**
     * Validates the TCP checksum of one IPv6 packet ([offset]/[length] view into
     * [frame]). The pseudo-header (source, destination, next header, TCP length)
     * plus the whole TCP segment — checksum field included — must fold to 0xffff
     * for a valid checksum. Returns false for truncated input.
     */
    private fun tcpChecksumValid(frame: ByteArray, offset: Int, length: Int): Boolean {
        if (length < 40 + 20 || offset < 0 || offset + length > frame.size) return false
        val tcpStart = offset + 40
        val tcpLength = length - 40
        var sum = 0L
        fun addWords(start: Int, bytes: Int) {
            var pos = start
            val end = start + bytes
            while (pos + 1 < end) {
                sum += (((frame[pos].toInt() and 0xff) shl 8) or (frame[pos + 1].toInt() and 0xff)).toLong()
                pos += 2
            }
            if (pos < end) sum += ((frame[pos].toInt() and 0xff) shl 8).toLong()
        }
        addWords(offset + 8, 32) // pseudo-header: source + destination
        sum += 6 // three zero bytes + next header (TCP)
        sum += tcpLength.toLong() // TCP length as 32 bits; high half is zero
        addWords(tcpStart, tcpLength)
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum == 0xffffL
    }

    private companion object {
        const val TAG = "xcertplay-usb"
        const val READ_TIMEOUT_MILLIS = 1_000L
        const val WRITE_TIMEOUT_MILLIS = 2_000
        const val TUN_READ_BYTES = 4_096
        const val ZERO_READ_BACKOFF_NANOS = 1_000_000L
        const val JOIN_TIMEOUT_MILLIS = 2_000L
        const val NA_RETRY_INTERVAL_NANOS = 500_000_000L
    }
}

/**
 * IP-redacted L4 summary of one inbound IPv6 packet for the user-exported diagnostic
 * report (issue #95): enough to tell "TCP SYN to port 7000 arrived" from "no TCP at all",
 * without leaking addresses. [offset] is the IPv6 header start within the Ethernet frame.
 */
internal fun ByteArray.diagnosticSummary(offset: Int): String {
    fun u16(at: Int): Int = ((this[at].toInt() and 0xff) shl 8) or (this[at + 1].toInt() and 0xff)
    val payloadBytes = size - offset
    if (payloadBytes < 44) return "bytes=$payloadBytes"
    val nextHeader = this[offset + 6].toInt() and 0xff
    val detail = when (nextHeader) {
        6 -> " tcp=->${u16(offset + 42)}"
        17 -> " udp=->${u16(offset + 42)}"
        58 -> " icmp6=${this[offset + 40].toInt() and 0xff}"
        else -> ""
    }
    return "bytes=$payloadBytes next=$nextHeader$detail"
}
