// To intercept low-level network traffic from the Linux kernel, we will use a Linux TAP device. 
// In short, a TUN/TAP device is often used by networking userspace applications to manipulate L3/L2 traffic, respectively. 

#pragma once

#include <string>

class TapInterface {
    public:
        TapInterface(const std::string& dev_name);
        ~TapInterface();

        int getFd() const;
        std::string getName() const;

    private:
        int fd;
        std::string name;

        void createTapDevice(const std::string& dev_name);
};
