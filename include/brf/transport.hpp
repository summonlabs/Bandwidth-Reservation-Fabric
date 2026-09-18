// Bandwidth Reservation Fabric - real TCP framed transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_TRANSPORT_HPP
#define BRF_TRANSPORT_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "brf/error.hpp"
#include "brf/protocol.hpp"

namespace brf {

/// One connected socket. Reads and writes are blocking: the fabric does not use
/// timeouts to paper over stuck peers, and a caller that abandons a request has
/// its session fenced explicitly instead.
class TcpSocket {
 public:
  TcpSocket() = default;
  ~TcpSocket();
  TcpSocket(TcpSocket&& other) noexcept;
  TcpSocket& operator=(TcpSocket&& other) noexcept;
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;

  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }

  /// Reads exactly one frame. Returns kCancelled when the peer closed cleanly
  /// between frames, and kCorrupt for malformed framing.
  [[nodiscard]] Result<protocol::Frame> read_frame(std::size_t max_frame_bytes);
  [[nodiscard]] Status write_frame(protocol::MessageType type, std::string_view payload);
  [[nodiscard]] Status write_bytes(std::string_view bytes);
  [[nodiscard]] Status read_exact(std::string_view buffer);

  /// Closes the socket. Safe to call from another thread to unblock a blocking
  /// read that this socket is parked in during shutdown.
  void close() noexcept;

  [[nodiscard]] std::uintptr_t raw_handle() const noexcept { return handle_; }

  /// Adopts an already connected handle. Used by TcpListener::accept and by
  /// connect_loopback; not part of the supported public surface.
  [[nodiscard]] static TcpSocket adopt(std::uintptr_t handle) noexcept;

 private:
  friend class TcpListener;
  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~static_cast<std::uintptr_t>(0));
  std::uintptr_t handle_ = kInvalidHandle;
};

/// Listening socket. Port 0 requests an ephemeral port, reported by port().
class TcpListener {
 public:
  TcpListener() = default;
  ~TcpListener();
  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  [[nodiscard]] static Result<TcpListener> bind_loopback(std::uint16_t port);
  [[nodiscard]] Result<TcpSocket> accept();
  void close() noexcept;
  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

 private:
  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~static_cast<std::uintptr_t>(0));
  std::uintptr_t handle_ = kInvalidHandle;
  std::uint16_t port_ = 0;
};

/// Connects to a loopback coordinator.
[[nodiscard]] Result<TcpSocket> connect_loopback(std::uint16_t port);

/// Initialises platform networking exactly once per process.
[[nodiscard]] Status transport_init();
void transport_shutdown() noexcept;

[[nodiscard]] std::string last_socket_error();

}  // namespace brf

#endif  // BRF_TRANSPORT_HPP
