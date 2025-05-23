#include "tuntap.hpp"
#include "syshead.hpp"

#include <cstring>
#include <iostream>

TapInterface::TapInterface(const std::string& dev_name) {
    createTapDevice(dev_name);
}

TapInterface::~TapInterface() {
    if (fd >= 0) {
        close(fd);
    }
}

int TapInterface::getFd() const {
    return fd;
}

std::string TapInterface::getName() const {
    return name;
}

void TapInterface::createTapDevice(const std::string& dev_name) {
    struct ifreq ifr {};
    const char* dev = dev_name.c_str();

    fd = open("/dev/net/tun", O_RDWR); // fd can be used to read and write data to the virtual device's ethernet buffer
    if (fd < 0) {
        perror("Cannot open TUN/TAP dev");
        exit(1);
    }

    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI; // IFF_NO_PI flag is crucial otherwise we end up with unnecessary packet information prepended to the Ethernet frame

    if (!dev_name.empty()) {
        std::strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
        perror("Could not ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    name = std::string(ifr.ifr_name);
}
