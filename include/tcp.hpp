#pragma once
#include <cstdint>
#include <unistd.h>

// 20‑byte TCP header (no options)
struct TcpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offset_reserved;  // high‑4 bits = header length in 32‑bit words
    uint8_t  flags;            // FIN=0x01, SYN=0x02, ACK=0x10, etc.
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPtr;
} __attribute__((packed));

// Called from handleIp() when protocol == TCP
void handleTcp(const uint8_t* packet,
               size_t        len,
               uint32_t      srcIp,
               uint32_t      dstIp,
               const uint8_t* srcMac,
               const uint8_t* ourMac,
               int           tapFd);
