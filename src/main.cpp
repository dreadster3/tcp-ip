#include "log.h"
#include "tun.h"
#include <csignal>

static bool running = true;
void signal_handler(int) { running = false; }

int main() {
  signal(SIGINT, signal_handler);
  TunDevice tun("tun69", 1500);

  try {
    tun.open();
    LOG_INFO("TUN interface {} created", tun.get_name());

    while (running) {
      LOG_TRACE("RUNNING");
    }
  } catch (const std::exception &e) {
    LOG_ERROR("{}", e.what());
    return -1;
  }

  LOG_INFO("TUN interface {} closed", tun.get_name());
  return 0;
}
