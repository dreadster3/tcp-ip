#include "tun.h"
#include "log.h"
#include "utils.h"
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <unistd.h>

TunDevice::TunDevice(std::string if_name, int mtu)
    : _if_name(std::move(if_name)), _mtu(mtu) {}

TunDevice::~TunDevice() {
  if (_fd >= 0) {
    ::close(_fd);
  }
}

void TunDevice::open() {
  if (_fd >= 0) {
    throw std::runtime_error("TUN device already open");
  }

  _fd = ::open("/dev/net/tun", O_RDWR);
  if (_fd < 0) {
    throw std::runtime_error("Failed to open TUN device: " +
                             std::string(::strerror(errno)));
  }
  LOG_DEBUG("Opened /dev/net/tun device: {}", _fd);

  struct ifreq ifr = {};
  std::strncpy(ifr.ifr_name, _if_name.c_str(), IFNAMSIZ);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  if (::ioctl(_fd, TUNSETIFF, &ifr) < 0) {
    ::close(_fd);
    _fd = -1;
    throw std::runtime_error("ioctl TUNSETIFF failed: " +
                             std::string(::strerror(errno)));
  }
  LOG_DEBUG("Interface {} attached to fd {}", _if_name, _fd);

  utils::cmd("ip link set dev {} up", _if_name);
  utils::cmd("ip route add {} dev {}", "10.10.10.0/24", _if_name);
  utils::cmd("ip addr add {} dev {}", "10.10.10.1", _if_name); //

  LOG_DEBUG("Interface {} initialized", _if_name);
}

std::size_t TunDevice::read(std::vector<uint8_t> &buffer) {
  buffer.resize(_mtu);
  auto n = ::read(_fd, buffer.data(), buffer.size());
  if (n < 0) {
    throw std::runtime_error("read failed: " + std::string(::strerror(errno)));
  }
  buffer.resize(n);

  LOG_DEBUG("Read {} bytes from TAP", n);
  return static_cast<std::size_t>(n);
}

std::size_t TunDevice::write(const std::vector<uint8_t> &buffer) {
  auto n = ::write(_fd, buffer.data(), buffer.size());
  if (n < 0) {
    throw std::runtime_error("write failed: " + std::string(::strerror(errno)));
  }

  LOG_DEBUG("Wrote {} bytes to TAP", n);
  return static_cast<std::size_t>(n);
}

std::string TunDevice::get_name() const { return _if_name; }

std::array<uint8_t, 6> TunDevice::get_mac() const {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0)
    throw std::runtime_error("socket: " + std::string(strerror(errno)));
  struct ifreq ifr{};
  std::strncpy(ifr.ifr_name, _if_name.c_str(), IFNAMSIZ);
  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    ::close(s);
    throw std::runtime_error("SIOCGIFHWADDR");
  }
  ::close(s);
  std::array<uint8_t, 6> m;
  std::memcpy(m.data(), ifr.ifr_hwaddr.sa_data, 6);
  return m;
};
