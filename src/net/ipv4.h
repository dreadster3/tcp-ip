#pragma once

#include "log.h"
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>

namespace net::ethernet::ipv4 {
inline uint32_t net_to_host_32(uint32_t net) { return __builtin_bswap32(net); }
inline uint16_t net_to_host(uint16_t net) { return __builtin_bswap16(net); }

inline std::string ip_to_string(uint32_t ip) {
  return std::format("{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                     (ip >> 8) & 0xFF, ip & 0xFF);
}

enum class Protocol : uint8_t { ICMP = 0x01, Unknown = 0x00 };

inline Protocol protocol_from_u8(uint8_t protocol) {
  switch (protocol) {
  case 0x01:
    return Protocol::ICMP;
  default:
    return Protocol::Unknown;
  }
}

inline std::string protocol_to_string(Protocol protocol) {
  switch (protocol) {
  case Protocol::ICMP:
    return "ICMP";
  default:
    return "Unknown";
  }
}

#pragma pack(push, 1)
struct Header {
  std::uint8_t version : 4;
  std::uint8_t internet_header_length : 4;
  std::uint8_t type_of_service;
  std::uint16_t length;
  std::uint16_t identification;
  std::uint16_t flags : 3;
  std::uint16_t fragment_offset : 13;
  std::uint8_t time_to_live;
  Protocol protocol;
  std::uint16_t checksum;
  std::uint32_t source;
  std::uint32_t destination;

  std::string to_string() const {
    return std::format("IPv4(version={}, ihl={}, tos={}, length={}, id={}, "
                       "flags={}, offset={}, ttl={}, protocol={}, checksum={}, "
                       "source={}, destination={})",
                       version, internet_header_length, type_of_service, length,
                       identification, flags, fragment_offset, time_to_live,
                       protocol_to_string(protocol), checksum,
                       ip_to_string(source), ip_to_string(destination));
  }
};
#pragma pack(pop)

inline uint16_t calculate_checksum(std::span<const uint8_t> packet) {
  uint32_t sum = 0;
  const uint16_t *p = reinterpret_cast<const uint16_t *>(packet.data());

  for (int i = 0; i < packet.size(); i += 2) {
    sum += p[i / 2];
  }

  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xffff);
  }
  return static_cast<uint16_t>(~sum);
}

inline std::optional<Header> parse(std::span<const uint8_t> packet,
                                   std::span<const uint8_t> &payload) {
  if (packet.size() < sizeof(Header)) {
    return std::nullopt;
  }

  Header header{};
  header.version = packet[0] >> 4;
  header.internet_header_length = packet[0] & 0x0f;

  if (header.version != 4 || header.internet_header_length < 5) {
    return std::nullopt;
  }

  header.type_of_service = packet[1];
  header.length = net_to_host((packet[2] << 8) | packet[3]);
  header.identification = net_to_host((packet[4] << 8) | packet[5]);
  header.flags = net_to_host(((packet[6] << 8 & packet[7]) >> 13) & 0x07);
  header.fragment_offset = net_to_host((packet[6] << 8 & packet[7]) & 0x1fff);
  header.time_to_live = packet[8];
  header.protocol = protocol_from_u8(packet[9]);
  header.checksum = net_to_host((packet[10] << 8) | packet[11]);
  header.source =
      (packet[12] << 24) | (packet[13] << 16) | (packet[14] << 8) | packet[15];
  header.destination =
      (packet[16] << 24) | (packet[17] << 16) | (packet[18] << 8) | packet[19];

  uint16_t checksum =
      calculate_checksum(packet.subspan(0, header.internet_header_length * 4));
  if (checksum != 0) {
    LOG_WARN("Error in checksum calculation: {}", checksum);
    return std::nullopt;
  }
  if (packet.size() > header.length) {
    LOG_WARN("Packet too large, size {} expected {}", packet.size(),
             header.length);
    return std::nullopt;
  }

  payload = packet.subspan(header.internet_header_length * 4);
  return header;
}
} // namespace net::ethernet::ipv4
