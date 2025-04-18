// The Address Resolution Protocol (ARP) is used for dynamically mapping a 48-bit Ethernet address (MAC address) to a 
// protocol address (e.g. IPv4 address). The key here is that with ARP, multitude of different L3 protocols can be used: 
// Not just IPv4, but other protocols like CHAOS, which declares 16-bit protocol addresses.

#ifndef ARP_HPP
#define ARP_HPP

#include <cstdint>

constexpr uint16_t ARP_HTYPE_ETHERNET = 0x0001;
constexpr uint16_t ARP_PTYPE_IPV4     = 0x0800;

constexpr uint8_t ARP_HLEN = 6;  // MAC address size
constexpr uint8_t ARP_PLEN = 4;  // IPv4 size

constexpr uint16_t ARP_REQUEST = 1;
constexpr uint16_t ARP_REPLY   = 2;

struct ArpHeader {
    uint16_t hwtype;
    uint16_t protype;
    uint8_t hwsize;
    uint8_t prosize;
    uint16_t opcode;
    unsigned char data[];
} __attribute__((packed));

struct ArpIPv4Payload {
    unsigned char smac[6];
    uint32_t sip;
    unsigned char dmac[6];
    uint32_t dip;
} __attribute__((packed));

struct ArpCacheEntry {
    uint32_t ip;
    uint8_t mac[6];
    bool resolved;
};

#endif