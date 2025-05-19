#include "tun.h"
#include "log.h"
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
}

std::string TunDevice::get_name() const { return _if_name; }
