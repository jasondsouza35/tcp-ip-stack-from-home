#ifndef TUNTAP_H
#define TUNTAP_H

#include <string>

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
