#include "arp.hpp"
#include "ethernet.hpp"
#include "tuntap.hpp"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>

// Hardcoded MAC broadcast address (ff:ff:ff:ff:ff:ff)
const uint8_t BROADCAST_MAC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

// A simple ARP cache that stores the last resolved IP and MAC
static uint32_t cached_ip = 0;
static uint8_t cached_mac[6] = {0};

/**
 * Inserts an IP-to-MAC mapping into the ARP cache.
 */
void insert_arp_cache(uint32_t ip, const uint8_t mac[6]) {
    cached_ip = ip;
    std::memcpy(cached_mac, mac, 6);
}

/**
 * Checks if a MAC address is known for the given IP.
 */
bool lookup_arp_cache(uint32_t ip, uint8_t out_mac[6]) {
    if (ip == cached_ip) {
        std::memcpy(out_mac, cached_mac, 6);
        return true;
    }
    return false;
}

/**
 * Sends an ARP reply in response to an ARP request.
 */
void send_arp_reply(int tap_fd, const uint8_t* dst_mac, uint32_t dst_ip,
                    const uint8_t* src_mac, uint32_t src_ip) {
    uint8_t buffer[1500] = {0};

    // Prepare the Ethernet header
    EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer);
    std::memcpy(eth->dmac, dst_mac, 6);
    std::memcpy(eth->smac, src_mac, 6);
    eth->ethertype = htons(ETH_TYPE_ARP);

    // Prepare the ARP header and payload
    ArpHeader* arp = reinterpret_cast<ArpHeader*>(eth->payload);
    arp->hw_type = htons(ARP_HTYPE_ETHERNET);
    arp->proto_type = htons(ARP_PTYPE_IPV4);
    arp->hw_size = 6;
    arp->proto_size = 4;
    arp->opcode = htons(ARP_REPLY);

    ArpIPv4Payload* data = reinterpret_cast<ArpIPv4Payload*>(arp->data);
    std::memcpy(data->smac, src_mac, 6);
    data->sip = htonl(src_ip);
    std::memcpy(data->dmac, dst_mac, 6);
    data->dip = htonl(dst_ip);

    // Total frame length = Ethernet + ARP header + ARP payload
    size_t len = sizeof(EthernetHeader) + sizeof(ArpHeader) + sizeof(ArpIPv4Payload);

    write(tap_fd, buffer, len);
    std::cout << "[ARP] Sent ARP reply" << std::endl;
}

/**
 * Handles an incoming ARP packet.
 */
void handle_arp(const uint8_t* packet, size_t len, const uint8_t* our_mac,
                uint32_t our_ip, int tap_fd) {
    if (len < sizeof(ArpHeader) + sizeof(ArpIPv4Payload)) {
        std::cerr << "[ARP] Packet too short" << std::endl;
        return;
    }

    const ArpHeader* arp = reinterpret_cast<const ArpHeader*>(packet);
    const ArpIPv4Payload* payload = reinterpret_cast<const ArpIPv4Payload*>(arp->data);

    // Convert fields from network to host byte order
    uint16_t hw_type = ntohs(arp->hw_type);
    uint16_t proto_type = ntohs(arp->proto_type);
    uint16_t opcode = ntohs(arp->opcode);
    uint32_t target_ip = ntohl(payload->dip);
    uint32_t sender_ip = ntohl(payload->sip);

    if (hw_type != ARP_HTYPE_ETHERNET || proto_type != ARP_PTYPE_IPV4) {
        std::cerr << "[ARP] Unsupported hardware or protocol type" << std::endl;
        return;
    }

    // Update the ARP cache with sender info
    insert_arp_cache(sender_ip, payload->smac);

    if (target_ip != our_ip) {
        std::cout << "[ARP] Not for us" << std::endl;
        return;
    }

    if (opcode == ARP_REQUEST) {
        std::cout << "[ARP] Received ARP request" << std::endl;
        send_arp_reply(tap_fd, payload->smac, sender_ip, our_mac, our_ip);
    }
}