#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class TunDevice {
public:
  explicit TunDevice(std::string if_name, int mtu = 1500);
  ~TunDevice();

  void open();

  std::string get_name() const;

  std::size_t read(std::vector<uint8_t> &buffer);
  std::size_t write(const std::vector<uint8_t> &buffer);

private:
  int _fd{-1};
  std::string _if_name;
  int _mtu;
};
