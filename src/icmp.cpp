#include "icmp.hpp"
#include "ip.hpp"
#include "ethernet.hpp"
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>

void handleIcmp(const uint8_t* packet, size_t len, uint32_t srcIp, uint32_t dstIp, int tapFd) {
    if (len < sizeof(IcmpHeader)) {
        std::cerr << "[ICMP] Packet too short" << std::endl;
        return;
    }

    const IcmpHeader* icmp = reinterpret_cast<const IcmpHeader*>(packet);
    if (icmp->type != ICMP_ECHO_REQUEST || icmp->code != 0) {
        return;  // Not an Echo Request we care about
    }

    std::cout << "[ICMP] Echo Request received, preparing Echo Reply" << std::endl;

    // Build ICMP Echo Reply
    uint8_t buffer[1500] = {0};
    EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer);
    IpHeader* ip = reinterpret_cast<IpHeader*>(eth->payload);
    IcmpHeader* reply = reinterpret_cast<IcmpHeader*>(ip + 1);  // Right after IP header

    // Ethernet layer (filled in by caller ideally)
    // Caller should prefill eth->dmac and eth->smac
    eth->ethertype = htons(ETH_TYPE_IPV4);

    // IP header
    ip->versionIhl = 0x45;  // Version 4, IHL = 5 (20 bytes)
    ip->tos = 0;
    ip->totalLength = htons(sizeof(IpHeader) + len);
    ip->id = htons(0x1234);
    ip->flagsFragOffset = htons(0);
    ip->ttl = 64;
    ip->protocol = 1;  // ICMP
    ip->checksum = 0;
    ip->srcIp = htonl(dstIp);
    ip->dstIp = htonl(srcIp);
    ip->checksum = ipChecksum(ip, sizeof(IpHeader));

    // ICMP header and payload
    std::memcpy(reply, packet, len);
    reply->type = ICMP_ECHO_REPLY;
    reply->checksum = 0;
    reply->checksum = ipChecksum(reply, len);

    // Total frame size
    size_t totalLen = sizeof(EthernetHeader) + sizeof(IpHeader) + len;
    write(tapFd, buffer, totalLen);
    std::cout << "[ICMP] Echo Reply sent" << std::endl;
}

void handleIp(const uint8_t* packet, size_t len, const uint8_t* ourMac, const uint8_t* srcMac, int tapFd) {
    if (len < sizeof(IpHeader)) {
        std::cerr << "[IP] Packet too short" << std::endl;
        return;
    }

    const IpHeader* ip = reinterpret_cast<const IpHeader*>(packet);

    if ((ip->versionIhl >> 4) != 4) {
        std::cerr << "[IP] Not IPv4" << std::endl;
        return;
    }

    size_t ipHeaderLen = (ip->versionIhl & 0x0F) * 4;
    if (ipHeaderLen < 20 || len < ipHeaderLen) {
        std::cerr << "[IP] Invalid IHL" << std::endl;
        return;
    }

    // Validate checksum
    if (ipChecksum(ip, ipHeaderLen) != 0) {
        std::cerr << "[IP] Bad checksum" << std::endl;
        return;
    }

    // Check if packet is for us
    uint32_t dstIp = ntohl(ip->dstIp);
    uint32_t srcIp = ntohl(ip->srcIp);

    // Only handle ICMP (protocol 1)
    if (ip->protocol == 1) {
        const uint8_t* icmpPayload = packet + ipHeaderLen;
        size_t icmpLen = ntohs(ip->totalLength) - ipHeaderLen;
        handleIcmp(icmpPayload, icmpLen, srcIp, dstIp, tapFd);
    }
}