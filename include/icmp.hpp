#pragma once
#include <cstdint>
#include <cstddef>

// The ICMP header resides in the payload of the corresponding IP packet.
struct IcmpHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t data[];
} __attribute__((packed));

// Echo Request/Reply messages, commonly referred to as “pinging” in networking.
struct IcmpEcho {
    uint16_t id;
    uint16_t seq;
    uint8_t data[];
} __attribute__((packed));

// ICMP Types
constexpr uint8_t ICMP_ECHO_REPLY   = 0;
constexpr uint8_t ICMP_ECHO_REQUEST = 8;

void handleIcmp(const uint8_t* packet,
    size_t        len,
    uint32_t      srcIp,
    uint32_t      dstIp,
    const uint8_t* srcMac,
    const uint8_t* ourMac,
    int           tapFd);
