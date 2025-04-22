// src/icmp.cpp

#include "icmp.hpp"
#include "ip.hpp"
#include "ethernet.hpp"
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>

// Compute a straightforward Internet checksum over `len` bytes at `data`
static uint16_t checksum(const void* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    while (len > 1) {
        sum += ntohs(*ptr++);
        len -= 2;
    }
    if (len > 0) {
        sum += (*reinterpret_cast<const uint8_t*>(ptr)) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(~sum);
}

void handleIcmp(const uint8_t* packet,
                size_t        len,
                uint32_t      srcIp,
                uint32_t      dstIp,
                const uint8_t* srcMac,
                const uint8_t* ourMac,
                int           tapFd)
{
    if (len < sizeof(IcmpHeader)) {
        std::cerr << "[ICMP] Packet too short ("<< len <<" bytes)\n";
        return;
    }

    auto* req = reinterpret_cast<const IcmpHeader*>(packet);
    if (req->type != ICMP_ECHO_REQUEST || req->code != 0) {
        return;
    }
    std::cout << "[ICMP] Echo Request received, sending Echo Reply\n";

    uint8_t buffer[1500] = {};
    auto* eth   = reinterpret_cast<EthernetHeader*>(buffer);
    auto* ip    = reinterpret_cast<IpHeader*>(eth->payload);
    auto* rep   = reinterpret_cast<IcmpHeader*>(
                    reinterpret_cast<uint8_t*>(ip) + sizeof(IpHeader)
                  );
    size_t icmpLen = len;  // header + payload

    // --- Ethernet header ---
    std::memcpy(eth->dmac, srcMac, 6);
    std::memcpy(eth->smac, ourMac, 6);
    eth->ethertype = htons(ETH_TYPE_IPV4);

    // --- IPv4 header ---
    ip->versionIhl      = (4 << 4) | (sizeof(IpHeader)/4);
    ip->tos             = 0;
    ip->totalLength     = htons(sizeof(IpHeader) + icmpLen);
    ip->id              = htons(0x1234);
    ip->flagsFragOffset = htons(0);
    ip->ttl             = 64;
    ip->protocol        = IPPROTO_ICMP;
    ip->srcIp           = htonl(dstIp);
    ip->dstIp           = htonl(srcIp);
    ip->checksum        = 0;
    ip->checksum        = ipChecksum(ip, sizeof(IpHeader));

    // --- ICMP header + payload ---
    std::memcpy(rep, packet, icmpLen);
    rep->type = ICMP_ECHO_REPLY;
    rep->checksum = 0;
    rep->checksum = checksum(rep, icmpLen);

    // --- Send frame ---
    size_t total = sizeof(EthernetHeader) + sizeof(IpHeader) + icmpLen;
    ssize_t written = write(tapFd, buffer, total);
    if (written == (ssize_t)total) {
        std::cout << "[ICMP] Echo Reply sent ("<< total <<" bytes)\n";
    } else {
        perror("[ICMP] write");
    }
}