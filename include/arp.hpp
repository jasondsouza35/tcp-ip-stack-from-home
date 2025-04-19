// The Address Resolution Protocol (ARP) is used for dynamically mapping a 48-bit Ethernet address (MAC address) to a 
// protocol address (e.g. IPv4 address). The key here is that with ARP, multitude of different L3 protocols can be used: 
// Not just IPv4, but other protocols like CHAOS, which declares 16-bit protocol addresses.

#pragma once
#include <cstdint>
#include <cstddef>

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

// Function declarations
void handleArp(const uint8_t* packet, size_t len, const uint8_t* ourMac, uint32_t ourIp, int tapFd);
void insertArpCache(uint32_t ip, const uint8_t mac[6]);
bool lookupArpCache(uint32_t ip, uint8_t out_mac[6]);
void sendArpCache(int tap_fd, const uint8_t* dst_mac, uint32_t dst_ip, const uint8_t* src_mac, uint32_t src_ip);
