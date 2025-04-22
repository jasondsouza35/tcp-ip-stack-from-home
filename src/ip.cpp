#include "ip.hpp"
#include "icmp.hpp"
#include "tcp.hpp"
#include "ethernet.hpp"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>

uint16_t ipChecksum(const void* data, int length) {
    uint32_t sum = 0;
    const uint16_t* ptr = static_cast<const uint16_t*>(data);

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length > 0) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
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

    if (ip->protocol == 1) {  // ICMP
        const uint8_t* payload = packet + ipHeaderLen;
        size_t icmpLen = ntohs(ip->totalLength) - ipHeaderLen;
        handleIcmp(payload, icmpLen, srcIp, dstIp, srcMac, ourMac, tapFd);
    } else if (ip->protocol == IPPROTO_TCP) {  // TCP
        const uint8_t* payload = packet + ipHeaderLen;
        size_t tcpLen = ntohs(ip->totalLength) - ipHeaderLen;
        handleTcp(payload, tcpLen, srcIp, dstIp, srcMac, ourMac, tapFd);
    }
}


