#pragma once

#include <chrono>
#include <ctime>
#include <format>
#include <iomanip>
#include <iostream>
#include <string_view>
enum LogLevel { TRACE, DEBUG, INFO, WARN, ERROR, FATAL };

#ifndef LOG_LEVEL
#define LOG_LEVEL LogLevel::INFO
#endif

inline constexpr LogLevel CURRENT_LOG_LEVEL = LOG_LEVEL;

inline const char *logLevelToString(LogLevel level) {
  switch (level) {
  case TRACE:
    return "TRC";
  case DEBUG:
    return "DBG";
  case INFO:
    return "INF";
  case WARN:
    return "WAR";
  case ERROR:
    return "ERR";
  default:
    return "UNK";
  }
}

template <typename... Args>
inline void log(LogLevel level, std::string_view fmt, Args &&...args) {
  if (level < CURRENT_LOG_LEVEL)
    return;

  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);

  std::tm tm{};
  localtime_r(&t, &tm);

  std::cerr << std::put_time(&tm, "%F %T") << " [" << logLevelToString(level)
            << "] " << std::format(std::runtime_format(fmt), args...)
            << std::endl;
}

#define LOG(level, fmt, ...) log(level, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) LOG(TRACE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG(DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) LOG(INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) LOG(WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG(ERROR, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) LOG(FATAL, fmt, ##__VA_ARGS__)
