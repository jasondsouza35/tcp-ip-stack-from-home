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

uint16_t ipChecksum(const void* data, int length);
