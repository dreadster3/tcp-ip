#pragma once

#include "ipv4.h"
#include "log.h"
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace net::ethernet::ipv4::icmp {
enum class PacketType : uint8_t { Reply = 0x00, Echo = 0x08, Unknown = 0x00 };

inline std::string type_to_string(PacketType type) {
  switch (type) {
  case PacketType::Echo:
    return "Echo";
  case PacketType::Reply:
    return "Reply";
  default:
    return "Unknown";
  }
};

inline PacketType to_type(uint8_t type) {
  switch (type) {
  case 0x08:
    return PacketType::Echo;
  case 0x00:
    return PacketType::Reply;
  default:
    return PacketType::Unknown;
  }
}

#pragma pack(push, 1)
struct Header {
  PacketType type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;

  std::string to_string() const {
    return std::format("ICMP(type={}, code={}, checksum={}, identifier={}, "
                       "sequence_number={})",
                       type_to_string(type), code, checksum, identifier,
                       sequence_number);
  }

  uint16_t calculate_checksum() const {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(this);
    return net::ethernet::ipv4::calculate_checksum({p, sizeof(Header)});
  }
};
#pragma pack(pop)

inline std::optional<Header> parse(std::span<const uint8_t> packet,
                                   std::span<const uint8_t> &payload) {
  if (packet.size() < sizeof(Header)) {
    return std::nullopt;
  }

  Header header{};
  header.type = to_type(packet[0]);
  header.code = packet[1];
  header.checksum = (packet[2] << 8) | packet[3];
  header.identifier = (packet[4] << 8) | packet[5];
  header.sequence_number = (packet[6] << 8) | packet[7];

  // Checksum

  payload = packet.subspan(8);
  return header;
}

inline void build(const Header &header, std::vector<uint8_t> &out) {
  out.clear();
  out.reserve(sizeof(Header));

  out.push_back((uint8_t)header.type);
  out.push_back(header.code);
  out.push_back((uint8_t)(header.checksum >> 8 & 0xFF));
  out.push_back((uint8_t)(header.checksum & 0xFF));
  out.push_back((uint8_t)(header.identifier >> 8 & 0xFF));
  out.push_back((uint8_t)(header.identifier & 0xFF));
  out.push_back((uint8_t)(header.sequence_number >> 8 & 0xFF));
}

} // namespace net::ethernet::ipv4::icmp
