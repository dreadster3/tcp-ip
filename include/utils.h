#pragma once

#include "log.h"
#include <cstdlib>
#include <format>
#include <string_view>

namespace utils {
template <typename... Args> int cmd(std::string_view fmt, Args &&...args) {
  std::string command = std::format(std::runtime_format(fmt), args...);
  LOG_TRACE(command);
  return ::system(std::move(command).c_str());
}
} // namespace utils
