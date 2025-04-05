#include "tuntap.h"
#include "syshead.h"

#include <cstring>
#include <iostream>

TapInterface::TapInterface(const std::string& dev_name) {
    create_tap_device(dev_name);
}

TapInterface::~TapInterface() {
    if (fd >= 0) {
        close(fd);
    }
}

int TapInterface::get_fd() const {
    return fd;
}

std::string TapInterface::get_name() const {
    return name;
}

void TapInterface::create_tap_device(const std::string& dev_name) {
    struct ifreq ifr {};
    const char* dev = dev_name.c_str();

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("Cannot open TUN/TAP dev");
        exit(1);
    }

    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

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
