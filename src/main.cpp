#include "tuntap.hpp"
#include "ethernet.hpp"
#include "arp.hpp"
#include "ip.hpp" 
#include "icmp.hpp"
#include "tcp.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    std::cout << "[MAIN] TCP/IP Stack Initialized" << std::endl;

    TapInterface tap("tap0");

    const char* ipStr = "10.0.0.4";
    uint32_t ourIp = 0;
    inet_pton(AF_INET, ipStr, &ourIp);

    uint8_t ourMac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    uint8_t buffer[1600];
    while (true) {
        ssize_t len = read(tap.getFd(), buffer, sizeof(buffer));
        if (len <= 0) continue;

        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer);
        uint16_t type = ntohs(eth->ethertype);

        if (type == ETH_TYPE_ARP) {
            handleArp(eth->payload, len - sizeof(EthernetHeader), ourMac, ntohl(ourIp), tap.getFd());
        } else if (type == ETH_TYPE_IPV4) {
            handleIp(eth->payload, len - sizeof(EthernetHeader), ourMac, eth->smac, tap.getFd());
        }
    }

    return 0;
}
