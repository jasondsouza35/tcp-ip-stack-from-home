#ifndef TUNTAP_H
#define TUNTAP_H

#include <string>

// To intercept low-level network traffic from the Linux kernel, we will use a Linux TAP device.
// TUN/TAP device is often used by networking userspace applications to manipulate L3/L2 traffic.
class TapInterface {
    public:
        TapInterface(const std::string& dev_name);
        ~TapInterface();

        int get_fd() const;
        std::string get_name() const;

    private:
        int fd;
        std::string name;

        void create_tap_device(const std::string& dev_name);
};

#endif
