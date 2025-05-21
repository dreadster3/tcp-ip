#pragma once

#include <cstdint>

namespace net::ethernet::ipv4 {
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
  std::uint8_t protocol;
  std::uint16_t checksum;
  std::uint32_t source;
  std::uint32_t destination;
};
#pragma pack(pop)
} // namespace net::ethernet::ipv4
