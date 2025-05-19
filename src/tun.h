#pragma once
#include <string>

class TunDevice {
public:
  explicit TunDevice(std::string if_name, int mtu = 1500);
  ~TunDevice();

  void open();

  std::string get_name() const;

private:
  int _fd{-1};
  std::string _if_name;
  int _mtu;
};
