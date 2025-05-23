#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace net::ethernet {
enum class PacketType : uint16_t {
  IPv4 = 0x0800,
  ARP = 0x0806,
  Unknown = 0x0000,
};

inline PacketType to_type(uint16_t type) {
  switch (type) {
  case 0x0800:
    return PacketType::IPv4;
  case 0x0806:
    return PacketType::ARP;
  default:
    return PacketType::Unknown;
  }
}

inline std::string packet_type_to_string(PacketType type) {
  switch (type) {
  case PacketType::IPv4:
    return "IPv4";
  case PacketType::ARP:
    return "ARP";
  default:
    return "Unknown";
  }
}

inline std::string mac_to_string(std::span<const uint8_t, 6> mac) {
  return std::format("{0:0>2x}:{1:0>2x}:{2:0>2x}:{3:0>2x}:{4:0>2x}:{5:0>2x}",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#pragma pack(push, 1)
struct Header {
  std::array<std::uint8_t, 6> src_mac;
  std::array<std::uint8_t, 6> dst_mac;
  PacketType type;

  std::string to_string() const {
    return std::format("Header(src={}, dst={}, type={})",
                       mac_to_string(src_mac), mac_to_string(dst_mac),
                       packet_type_to_string(type));
  }
};
#pragma pack(pop)

inline std::optional<Header> parse(std::span<const uint8_t> frame,
                                   std::span<const uint8_t> &payload) {
  if (frame.size() < sizeof(Header)) {
    return std::nullopt;
  }

  Header header;

  std::memcpy(header.dst_mac.data(), frame.data(), 6);
  std::memcpy(header.src_mac.data(), frame.data() + 6, 6);
  uint16_t protocol = (frame[12] << 8) | frame[13];
  header.type = to_type(protocol);

  payload = frame.subspan(14);
  return header;
}

inline void build(const Header &header, std::span<const uint8_t> payload,
                  std::vector<uint8_t> &out) {
  out.clear();
  out.reserve(sizeof(Header) + payload.size());
  out.insert(out.end(), header.dst_mac.begin(), header.dst_mac.end());
  out.insert(out.end(), header.src_mac.begin(), header.src_mac.end());
  out.push_back(((uint16_t)header.type >> 8) & 0xFF);
  out.push_back(((uint16_t)header.type) & 0xFF);
  out.insert(out.end(), payload.begin(), payload.end());
}

} // namespace net::ethernet
