#pragma once

#include "ethernet.h"
#include "ipv4.h"
#include <cstdint>
#include <optional>
#include <string>

namespace net::ethernet::arp {
#pragma pack(push, 1)
struct Header {
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t hardware_length;
  uint8_t protocol_length;
  uint16_t opcode;
  std::array<uint8_t, 6> source_mac_address;
  uint32_t source_ip;
  std::array<uint8_t, 6> destination_mac_address;
  uint32_t destination_ip;

  std::string to_string() const {
    return std::format(
        "ARP(hardware_type={}, protocol_type={}, "
        "hardware_length={}, protocol_length={}, opcode={}, "
        "source_mac_address={}, source_ip={}, "
        "destination_mac_address={}, destination_ip={})",
        hardware_type, protocol_type, hardware_length, protocol_length, opcode,
        mac_to_string(source_mac_address), ipv4::ip_to_string(source_ip),
        mac_to_string(destination_mac_address),
        ipv4::ip_to_string(destination_ip));
  }
};
#pragma pack(pop)

inline std::optional<Header> parse(std::span<const uint8_t> pkt) {
  if (pkt.size() < sizeof(Header)) {
    return std::nullopt;
  }

  Header header{};
  header.hardware_type = (pkt[0] << 8) | pkt[1];
  header.protocol_type = (pkt[2] << 8) | pkt[3];
  header.hardware_length = pkt[4];
  header.protocol_length = pkt[5];
  header.opcode = (pkt[6] << 8) | pkt[7];
  std::memcpy(header.source_mac_address.data(), pkt.data() + 8, 6);
  header.source_ip =
      (pkt[14] << 24) | (pkt[15] << 16) | (pkt[16] << 8) | pkt[17];
  std::memcpy(header.destination_mac_address.data(), pkt.data() + 18, 6);
  header.destination_ip =
      (pkt[24] << 24) | (pkt[25] << 16) | (pkt[26] << 8) | pkt[27];

  return header;
}

inline void build(const Header &header, std::vector<uint8_t> &out) {
  out.clear();
  out.resize(sizeof(Header));
  out[0] = (header.hardware_type >> 8) & 0xff;
  out[1] = header.hardware_type & 0xff;
  out[2] = (header.protocol_type >> 8) & 0xff;
  out[3] = header.protocol_type & 0xff;
  out[4] = header.hardware_length;
  out[5] = header.protocol_length;
  out[6] = (header.opcode >> 8) & 0xff;
  out[7] = header.opcode & 0xff;
  std::memcpy(out.data() + 8, header.source_mac_address.data(), 6);
  out[14] = (header.source_ip >> 24) & 0xff;
  out[15] = (header.source_ip >> 16) & 0xff;
  out[16] = (header.source_ip >> 8) & 0xff;
  out[17] = header.source_ip & 0xff;
  std::memcpy(out.data() + 18, header.destination_mac_address.data(), 6);
  out[24] = (header.destination_ip >> 24) & 0xff;
  out[25] = (header.destination_ip >> 16) & 0xff;
  out[26] = (header.destination_ip >> 8) & 0xff;
  out[27] = header.destination_ip & 0xff;
}
} // namespace net::ethernet::arp
