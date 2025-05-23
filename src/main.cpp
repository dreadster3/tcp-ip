#include "log.h"
#include "net/arp.h"
#include "net/ethernet.h"
#include "net/icmp.h"
#include "net/ipv4.h"
#include "tun.h"
#include <csignal>
#include <cstdint>
#include <vector>

static bool running = true;
void signal_handler(int) { running = false; }

int main() {
  signal(SIGINT, signal_handler);
  uint32_t ip_address = 0x0A0A0A05;
  std::array<uint8_t, 6> mac = {0xBA, 0x14, 0x16, 0x19, 0x10, 0x1B};
  TunDevice tap("tap69", 1500);
  std::vector<uint8_t> frame, reply;

  try {
    tap.open();
    LOG_INFO("TUN interface {} created", tap.get_name());

    while (running) {
      auto n = tap.read(frame);
      LOG_INFO("Read {} bytes", n);

      std::span<const uint8_t> packet;
      auto ethernet_header = net::ethernet::parse(frame, packet);

      if (!ethernet_header)
        continue;

      LOG_INFO("Ethernet packet received");
      LOG_DEBUG("Ethernet Header: {}", ethernet_header->to_string());

      switch (ethernet_header->type) {
      case net::ethernet::PacketType::ARP: {
        auto arp_header = net::ethernet::arp::parse(packet);
        if (!arp_header) {
          continue;
        }

        LOG_INFO("ARP packet received");
        LOG_DEBUG("ARP Header: {}", arp_header->to_string());

        if (arp_header->opcode != 1 ||
            arp_header->destination_ip != ip_address) {
          continue;
        }

        auto reply_header = net::ethernet::arp::Header();
        reply_header.hardware_type = 0x0001;
        reply_header.protocol_type = 0x0800;
        reply_header.hardware_length = 0x06;
        reply_header.protocol_length = 0x04;
        reply_header.opcode = 0x02;
        reply_header.source_mac_address = mac;
        reply_header.source_ip = arp_header->destination_ip;
        reply_header.destination_mac_address = arp_header->source_mac_address;
        reply_header.destination_ip = arp_header->source_ip;
        LOG_DEBUG("ARP reply: {}", reply_header.to_string());

        std::vector<uint8_t> reply_arp_packet;
        net::ethernet::arp::build(reply_header, reply_arp_packet);
        LOG_TRACE("Successfully built ARP reply (size {})",
                  reply_arp_packet.size());

        auto reply_ethernet_header = net::ethernet::Header();
        reply_ethernet_header.type = net::ethernet::PacketType::ARP;
        reply_ethernet_header.src_mac = mac;
        reply_ethernet_header.dst_mac = ethernet_header->src_mac;
        LOG_DEBUG("ARP reply ethernet: {}", reply_ethernet_header.to_string());

        net::ethernet::build(reply_ethernet_header, reply_arp_packet, reply);
        LOG_TRACE("Successfully built ARP ethernet reply (size {})",
                  reply.size());
        n = tap.write(reply);
        LOG_DEBUG("Successfully sent ARP reply: {}", n);

        break;
      }
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

            auto icmp_reply_header = net::ethernet::ipv4::icmp::Header();
            icmp_reply_header.type =
                net::ethernet::ipv4::icmp::PacketType::Reply;
            icmp_reply_header.code = 0;
            icmp_reply_header.identifier = icmp_header->identifier;
            icmp_reply_header.sequence_number = icmp_header->sequence_number;
            icmp_reply_header.checksum = icmp_header->calculate_checksum();

            std::vector<uint8_t> icmp_reply_packet;
            net::ethernet::ipv4::icmp::build(icmp_reply_header,
                                             icmp_reply_packet);
            LOG_DEBUG("ICMP reply: {}", icmp_reply_header.to_string());

            auto ipv4_reply_header = net::ethernet::ipv4::Header();
            ipv4_reply_header.internet_header_length = 5;
            ipv4_reply_header.version = 4;
            ipv4_reply_header.protocol = net::ethernet::ipv4::Protocol::ICMP;
            ipv4_reply_header.type_of_service = 0;
            ipv4_reply_header.identification = ipv4_header->identification + 1;
            ipv4_reply_header.flags = 0;
            ipv4_reply_header.fragment_offset = 0;
            ipv4_reply_header.time_to_live = 64;
            ipv4_reply_header.source = ip_address;
            ipv4_reply_header.destination = ipv4_header->source;
            ipv4_reply_header.length = net::ethernet::ipv4::htons(
                ipv4_reply_header.internet_header_length * 4 +
                icmp_reply_packet.size());
            ipv4_reply_header.checksum = ipv4_reply_header.calculate_checksum();

            std::vector<uint8_t> ipv4_reply_packet;
            net::ethernet::ipv4::build(ipv4_reply_header, icmp_reply_packet,
                                       ipv4_reply_packet);
            LOG_DEBUG("IPv4 reply: {}", ipv4_reply_header.to_string());

            auto ethernet_reply_header = net::ethernet::Header();
            ethernet_reply_header.type = net::ethernet::PacketType::IPv4;
            ethernet_reply_header.src_mac = mac;
            ethernet_reply_header.dst_mac = ethernet_header->src_mac;

            net::ethernet::build(ethernet_reply_header, ipv4_reply_packet,
                                 reply);
            LOG_DEBUG("Ethernet reply: {}", ethernet_reply_header.to_string());

            tap.write(reply);
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
    }
  } catch (const std::exception &e) {
    LOG_ERROR("{}", e.what());
    return -1;
  }

  LOG_INFO("TUN interface {} closed", tap.get_name());
  return 0;
}
