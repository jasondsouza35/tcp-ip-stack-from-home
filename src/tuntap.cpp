#include "tuntap.h"
#include "syshead.h"

#include <cstring>
#include <iostream>

tap_interface::tap_interface(const std::string& dev_name) {
    create_tap_device(dev_name);
}

tap_interface::~tap_interface() {
    if (fd >= 0) {
        close(fd);
    }
}

int tap_interface::get_fd() const {
    return fd;
}

std::string tap_interface::get_name() const {
    return name;
}

void tap_interface::create_tap_device(const std::string& dev_name) {
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
