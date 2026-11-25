#pragma once
// Minimal logging shim: real CTranslate2 model.cc only calls spdlog::info/warn
#include <mutex>
// for logging; no formatting is needed to exercise Model::load.
namespace spdlog {
  template <typename... Args> inline void info(Args&&...) {}
  template <typename... Args> inline void warn(Args&&...) {}
  template <typename... Args> inline void error(Args&&...) {}
  template <typename... Args> inline void debug(Args&&...) {}
}
