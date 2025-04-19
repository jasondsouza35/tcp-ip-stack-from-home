#include "ip.hpp"
#include "icmp.hpp"
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