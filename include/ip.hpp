#pragma once
#include <cstdint>

struct IpHeader {
    uint8_t versionIhl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t id;
    uint16_t flagsFragOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t srcIp;
    uint32_t dstIp;
} __attribute__((packed));

// The Internet checksum field is used to check the integrity of an IP datagram.
// The checksum field is the 16 bit one’s complement of the one’s complement sum of all 16 bit words in the header.
// For purposes of computing the checksum, the value of the checksum field is zero.
uint16_t ipChecksum(const void* data, int length);