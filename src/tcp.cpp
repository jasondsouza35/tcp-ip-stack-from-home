#include "tcp.hpp"
#include "ip.hpp"
#include "ethernet.hpp"
#include "syshead.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <unistd.h>

// TCP flag definitions
static constexpr uint8_t TCP_FLAG_FIN = 0x01;
static constexpr uint8_t TCP_FLAG_SYN = 0x02;
static constexpr uint8_t TCP_FLAG_RST = 0x04;
static constexpr uint8_t TCP_FLAG_PSH = 0x08;
static constexpr uint8_t TCP_FLAG_ACK = 0x10;
static constexpr uint8_t TCP_FLAG_URG = 0x20;

// Compute TCP checksum: pseudo-header + TCP header + payload
static uint16_t pseudoChecksum(const IpHeader* ip,
                               const TcpHeader* tcp,
                               std::size_t tcpLen)
{
    uint32_t sum = 0;

    // 1) Pseudo-header: source and dest IPs (host order)
    uint32_t src = ntohl(ip->srcIp);
    uint32_t dst = ntohl(ip->dstIp);
    sum += (src >> 16) & 0xFFFF;
    sum += src & 0xFFFF;
    sum += (dst >> 16) & 0xFFFF;
    sum += dst & 0xFFFF;

    sum += IPPROTO_TCP;   // protocol
    sum += tcpLen;        // TCP length

    // 2) Copy TCP segment into buffer
    static uint8_t buf[1600];
    std::memcpy(buf, tcp, tcpLen);
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(buf);

    // 3) Sum TCP header and payload
    for (std::size_t i = 0; i < tcpLen/2; ++i) {
        sum += ntohs(ptr[i]);
    }
    if (tcpLen & 1) {
        sum += (buf[tcpLen - 1] << 8);
    }

    // 4) Fold carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

void handleTcp(const uint8_t* packet,
               std::size_t   len,
               uint32_t      srcIp,
               uint32_t      dstIp,
               const uint8_t* srcMac,
               const uint8_t* ourMac,
               int           tapFd)
{
    if (len < sizeof(TcpHeader)) {
        std::cerr << "[TCP] Packet too short ("<< len <<" bytes)\n";
        return;
    }

    // Parse the incoming TCP header
    auto* tcp = reinterpret_cast<const TcpHeader*>(packet);
    uint16_t sport  = ntohs(tcp->srcPort);
    uint16_t dport  = ntohs(tcp->dstPort);
    uint32_t seqNum = ntohl(tcp->seq);
    uint32_t ackNum = ntohl(tcp->ack);
    uint8_t  flags   = tcp->flags;

    std::cout << "[TCP] segment: sport="<< sport
              << " dport="  << dport
              << " seq="    << seqNum
              << " ack="    << ackNum
              << " flags=0x"<< std::hex << int(flags) << std::dec <<"\n";

    // Final ACK of the handshake?
    if ((flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN)) {
        std::cout << "[TCP] Final ACK received, connection established\n";
        return;
    }

    // Only handle SYNs for now
    if (!(flags & TCP_FLAG_SYN)) {
        return;
    }

    std::cout << "[TCP] SYN received, sending SYN+ACK\n";

    // Build Ethernet + IPv4 + TCP reply
    uint8_t buffer[1500] = {0};
    auto* eth   = reinterpret_cast<EthernetHeader*>(buffer);
    auto* ip    = reinterpret_cast<IpHeader*>(eth->payload);
    auto* reply = reinterpret_cast<TcpHeader*>(reinterpret_cast<uint8_t*>(ip) + sizeof(IpHeader));

    // --- Ethernet header ---
    std::memcpy(eth->dmac, srcMac, 6);
    std::memcpy(eth->smac, ourMac, 6);
    eth->ethertype = htons(ETH_TYPE_IPV4);

    // --- IP header ---
    ip->versionIhl      = (4 << 4) | (sizeof(IpHeader)/4);
    ip->tos             = 0;
    ip->totalLength     = htons(sizeof(IpHeader) + sizeof(TcpHeader));
    ip->id              = htons(0x1234);
    ip->flagsFragOffset = htons(0);
    ip->ttl             = 64;
    ip->protocol        = IPPROTO_TCP;
    ip->checksum        = 0;
    ip->srcIp           = htonl(dstIp);
    ip->dstIp           = htonl(srcIp);
    ip->checksum        = ipChecksum(ip, sizeof(IpHeader));

    // --- TCP header ---
    reply->srcPort        = htons(dport);
    reply->dstPort        = htons(sport);
    reply->seq            = htonl(0x1000);                  // our ISN
    reply->ack            = htonl(seqNum + 1);              // ack their SYN
    reply->offset_reserved = (sizeof(TcpHeader)/4) << 4;
    reply->flags          = TCP_FLAG_SYN | TCP_FLAG_ACK;
    reply->window         = htons(65535);
    reply->checksum       = 0;
    reply->urgentPtr      = 0;
    reply->checksum       = pseudoChecksum(ip, reply, sizeof(TcpHeader));

    size_t totalLen = sizeof(EthernetHeader)
                    + sizeof(IpHeader)
                    + sizeof(TcpHeader);

    ssize_t written = write(tapFd, buffer, totalLen);
    if (written == (ssize_t)totalLen) {
        std::cout << "[TCP] SYN+ACK sent ("<< totalLen <<" bytes)\n";
    } else {
        perror("[TCP] write");
    }
}
