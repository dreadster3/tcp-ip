#include "log.h"
#include "net/ethernet.h"
#include "net/icmp.h"
#include "net/ipv4.h"
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

      std::span<const uint8_t> packet;
      auto ethernet_header = net::ethernet::parse_header(frame, packet);

      if (!ethernet_header)
        continue;

      LOG_INFO("Ethernet packet received");
      LOG_DEBUG("Ethernet Header: {}", ethernet_header->to_string());

      switch (ethernet_header->type) {
      case net::ethernet::PacketType::IPv4: {
        std::span<const uint8_t> ipv4_data;
        auto ipv4_header = net::ethernet::ipv4::parse(packet, ipv4_data);
        if (ipv4_header) {
          LOG_INFO("IPv4 packet received");
          LOG_DEBUG("IPv4 Header: {}", ipv4_header->to_string());
          switch (ipv4_header->protocol) {
          case net::ethernet::ipv4::Protocol::ICMP: {
            std::span<const uint8_t> icmp_data;

            auto icmp_header =
                net::ethernet::ipv4::icmp::parse(ipv4_data, icmp_data);
            if (!icmp_header) {
              continue;
            }

            LOG_INFO("ICMP packet received");
            LOG_DEBUG("ICMP Header: {}", icmp_header->to_string());
            break;
          }
          default:
            LOG_WARN(
                "IPv4 protocol {} not supported",
                net::ethernet::ipv4::protocol_to_string(ipv4_header->protocol));
            break;
          }
        }
        break;
      }
      default:
        LOG_WARN("Packet type {} not supported",
                 net::ethernet::packet_type_to_string(ethernet_header->type));
        break;
      }

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
