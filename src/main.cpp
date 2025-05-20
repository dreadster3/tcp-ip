#include "log.h"
#include "tun.h"
#include <csignal>
#include <vector>

static bool running = true;
void signal_handler(int) { running = false; }

int main() {
  signal(SIGINT, signal_handler);
  TunDevice tap("tap69", 1500);
  std::vector<uint8_t> frame;

  try {
    tap.open();
    LOG_INFO("TUN interface {} created", tap.get_name());

    while (running) {
      auto n = tap.read(frame);
      LOG_INFO("Read {} bytes", n);
      n = tap.write(frame);
      LOG_INFO("Wrote {} bytes", n);
    }
  } catch (const std::exception &e) {
    LOG_ERROR("{}", e.what());
    return -1;
  }

  LOG_INFO("TUN interface {} closed", tap.get_name());
  return 0;
}
