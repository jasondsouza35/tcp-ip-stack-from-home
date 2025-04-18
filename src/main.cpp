#include "tuntap.hpp"
#include "ethernet.hpp"
#include "arp.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    std::cout << "[MAIN] TCP/IP Stack Initialized" << std::endl;

    // 1. Create the TAP interface named "tap0"
    TapInterface tap("tap0");

    // 2. Define our local IP and MAC address
    const char* ipStr = "10.0.0.4";
    uint32_t ourIp = 0;
    inet_pton(AF_INET, ipStr, &ourIp);  // Converts IP string to network byte order

    uint8_t ourMac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};  // Static MAC for testing

    // 3. Listen and respond to ARP requests
    uint8_t buffer[1600];
    while (true) {
        ssize_t len = read(tap.getFd(), buffer, sizeof(buffer));
        if (len <= 0) continue;

        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer);
        if (ntohs(eth->ethertype) == ETH_TYPE_ARP) {
            handleArp(eth->payload, len - sizeof(EthernetHeader), ourMac, ntohl(ourIp), tap.getFd());
        }
    }

    return 0;
}