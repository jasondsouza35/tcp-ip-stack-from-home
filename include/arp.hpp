// The Address Resolution Protocol (ARP) is used for dynamically mapping a 48-bit Ethernet address (MAC address) to a 
// protocol address (e.g. IPv4 address). The key here is that with ARP, multitude of different L3 protocols can be used: 
// Not just IPv4, but other protocols like CHAOS, which declares 16-bit protocol addresses.

#pragma once
#include <cstdint>

// ARP header (fixed size portion)
struct ArpHeader {
    uint16_t hwType;
    uint16_t protoType;
    uint8_t hwSize;
    uint8_t protoSize;
    uint16_t opcode;
    uint8_t data[];
} __attribute__((packed));

// ARP payload specific to IPv4
struct ArpIPv4Payload {
    uint8_t senderMac[6];
    uint32_t senderIp;
    uint8_t targetMac[6];
    uint32_t targetIp;
} __attribute__((packed));

// ARP protocol constants
constexpr uint16_t ARP_HTYPE_ETHERNET = 0x0001;
constexpr uint16_t ARP_PTYPE_IPV4     = 0x0800;
constexpr uint16_t ARP_REQUEST        = 1;
constexpr uint16_t ARP_REPLY          = 2;