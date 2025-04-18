// To intercept low-level network traffic from the Linux kernel, we will use a Linux TAP device. 
// In short, a TUN/TAP device is often used by networking userspace applications to manipulate L3/L2 traffic, respectively. 

#ifndef TUNTAP_H
#define TUNTAP_H

#include <string>

class tap_interface {
    public:
        tap_interface(const std::string& dev_name);
        ~tap_interface();

        int get_fd() const;
        std::string get_name() const;

    private:
        int fd;
        std::string name;

        void create_tap_device(const std::string& dev_name);
};

#endif
