#ifndef ETHERNET_H
#define ETHERNET_H

#include <cstdint>

// Ethernet Frame header - cast raw bytes from the TAP device into a usable form
struct EthernetHeader {
    uint8_t dmac[6];      // Destination MAC
    uint8_t smac[6];      // Source MAC
    uint16_t ethertype;   // Type of payload (ARP, IPv4, etc.)
    uint8_t payload[];    // Payload data (flexible array)
} __attribute__((packed)); // Tells the compiler to not add any extra padding - keeps the struct exactly 14 bytes

constexpr uint16_t ETH_TYPE_ARP = 0x0806;
constexpr uint16_t ETH_TYPE_IPV4 = 0x0800;

#endif ETHERNET_H