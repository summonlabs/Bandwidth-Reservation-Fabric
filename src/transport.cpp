// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Real TCP transport. Frames are length-prefixed and CRC checked; a malformed
// or oversized frame is refused rather than accommodated.
#include "brf/transport.hpp"

#include <atomic>
#include <cstring>
#include <string>

#include "brf/hash.hpp"

#include "brf/hash.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace brf {
namespace {

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

std::atomic<bool> g_transport_ready{false};

[[nodiscard]] SocketHandle to_socket(std::uintptr_t handle) noexcept {
  return static_cast<SocketHandle>(handle);
}

[[nodiscard]] std::uintptr_t from_socket(SocketHandle handle) noexcept {
  return static_cast<std::uintptr_t>(handle);
}

[[nodiscard]] bool socket_valid(SocketHandle handle) noexcept { return handle != kInvalidSocket; }

void close_socket(SocketHandle handle) noexcept {
  if (!socket_valid(handle)) return;
#ifdef _WIN32
  ::closesocket(handle);
#else
  ::close(handle);
#endif
}

[[nodiscard]] Status send_all(SocketHandle handle, const char* data, std::size_t size) {
  std::size_t sent = 0;
  while (sent < size) {
#ifdef _WIN32
    const int chunk = ::send(handle, data + sent, static_cast<int>(size - sent), 0);
#else
    const ssize_t chunk = ::send(handle, data + sent, size - sent, MSG_NOSIGNAL);
#endif
    if (chunk <= 0) {
      return make_error(ErrorCode::kIo, "socket send failed: " + last_socket_error());
    }
    sent += static_cast<std::size_t>(chunk);
  }
  return {};
}

[[nodiscard]] Result<std::size_t> receive_some(SocketHandle handle, char* buffer, std::size_t size) {
#ifdef _WIN32
  const int received = ::recv(handle, buffer, static_cast<int>(size), 0);
#else
  const ssize_t received = ::recv(handle, buffer, size, 0);
#endif
  if (received == 0) {
    return std::size_t{0};  // Peer closed.
  }
  if (received < 0) {
    return make_error(ErrorCode::kIo, "socket receive failed: " + last_socket_error());
  }
  return static_cast<std::size_t>(received);
}

[[nodiscard]] Status receive_exact(SocketHandle handle, char* buffer, std::size_t size) {
  std::size_t received = 0;
  while (received < size) {
    Result<std::size_t> chunk = receive_some(handle, buffer + received, size - received);
    if (!chunk) return chunk.error();
    if (chunk.value() == 0) {
      return make_error(ErrorCode::kCancelled, "peer closed the connection");
    }
    received += chunk.value();
  }
  return {};
}

}  // namespace

Status transport_init() {
  if (g_transport_ready.load()) return {};
#ifdef _WIN32
  WSADATA data;
  if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
    return make_error(ErrorCode::kIo, "WSAStartup failed");
  }
#endif
  g_transport_ready.store(true);
  return {};
}

void transport_shutdown() noexcept {
#ifdef _WIN32
  if (g_transport_ready.exchange(false)) {
    ::WSACleanup();
  }
#else
  g_transport_ready.store(false);
#endif
}

std::string last_socket_error() {
#ifdef _WIN32
  return "winsock error " + std::to_string(::WSAGetLastError());
#else
  return std::string(std::strerror(errno));
#endif
}

TcpSocket TcpSocket::adopt(std::uintptr_t handle) noexcept {
  TcpSocket socket;
  socket.handle_ = handle;
  return socket;
}

TcpSocket::~TcpSocket() { close(); }

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : handle_(other.handle_) {
  other.handle_ = kInvalidHandle;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kInvalidHandle;
  }
  return *this;
}

void TcpSocket::close() noexcept {
  if (handle_ != kInvalidHandle) {
    close_socket(to_socket(handle_));
    handle_ = kInvalidHandle;
  }
}

Status TcpSocket::write_bytes(std::string_view bytes) {
  if (!valid()) return make_error(ErrorCode::kIo, "socket is not connected");
  return send_all(to_socket(handle_), bytes.data(), bytes.size());
}

Status TcpSocket::write_frame(protocol::MessageType type, std::string_view payload) {
  if (payload.size() > protocol::kMaxFrameBytes) {
    return make_error(ErrorCode::kResourceExhausted, "frame exceeds the maximum size");
  }
  const std::string frame = protocol::encode_frame(type, payload);
  return write_bytes(frame);
}

Status TcpSocket::read_exact(std::string_view buffer) {
  if (!valid()) return make_error(ErrorCode::kIo, "socket is not connected");
  return receive_exact(to_socket(handle_), const_cast<char*>(buffer.data()), buffer.size());
}

Result<protocol::Frame> TcpSocket::read_frame(std::size_t max_frame_bytes) {
  if (!valid()) return make_error(ErrorCode::kIo, "socket is not connected");
  std::string header(protocol::kFrameHeaderBytes, '\0');
  Status received = receive_exact(to_socket(handle_), header.data(), header.size());
  if (!received) return received.error();
  Reader reader(header);
  Result<std::uint32_t> magic = reader.u32();
  if (!magic) return magic.error();
  if (magic.value() != protocol::kFrameMagic) {
    return make_error(ErrorCode::kCorrupt, "frame magic is invalid");
  }
  Result<std::uint32_t> length = reader.u32();
  if (!length) return length.error();
  if (length.value() < protocol::kFrameHeaderBytes || length.value() > max_frame_bytes) {
    return make_error(ErrorCode::kResourceExhausted, "frame declares an unsupported length");
  }
  Result<std::uint32_t> checksum = reader.u32();
  if (!checksum) return checksum.error();
  Result<std::uint16_t> type = reader.u16();
  if (!type) return type.error();
  Result<std::uint16_t> version = reader.u16();
  if (!version) return version.error();
  if (version.value() != kWireProtocolVersion) {
    return make_error(ErrorCode::kUnsupported, "frame protocol version is not supported");
  }
  const std::size_t payload_size = length.value() - protocol::kFrameHeaderBytes;
  std::string payload(payload_size, '\0');
  if (payload_size > 0) {
    Status body = receive_exact(to_socket(handle_), payload.data(), payload_size);
    if (!body) return body.error();
  }
  if (crc32c(payload.data(), payload.size()) != checksum.value()) {
    return make_error(ErrorCode::kCorrupt, "frame checksum mismatch");
  }
  protocol::Frame frame;
  frame.type = static_cast<protocol::MessageType>(type.value());
  frame.payload = std::move(payload);
  return frame;
}

TcpListener::~TcpListener() { close(); }

TcpListener::TcpListener(TcpListener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
  other.handle_ = kInvalidHandle;
  other.port_ = 0;
}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = kInvalidHandle;
    other.port_ = 0;
  }
  return *this;
}

void TcpListener::close() noexcept {
  if (handle_ != kInvalidHandle) {
    close_socket(to_socket(handle_));
    handle_ = kInvalidHandle;
  }
}

Result<TcpListener> TcpListener::bind_loopback(std::uint16_t port) {
  Status ready = transport_init();
  if (!ready) return ready.error();
  SocketHandle handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (!socket_valid(handle)) {
    return make_error(ErrorCode::kIo, "socket creation failed: " + last_socket_error());
  }
  int reuse = 1;
  ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  address.sin_port = ::htons(port);
  if (::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close_socket(handle);
    return make_error(ErrorCode::kIo, "bind failed: " + last_socket_error());
  }
  if (::listen(handle, 64) != 0) {
    close_socket(handle);
    return make_error(ErrorCode::kIo, "listen failed: " + last_socket_error());
  }
  sockaddr_in bound{};
#ifdef _WIN32
  int bound_size = sizeof(bound);
#else
  socklen_t bound_size = sizeof(bound);
#endif
  if (::getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &bound_size) != 0) {
    close_socket(handle);
    return make_error(ErrorCode::kIo, "getsockname failed: " + last_socket_error());
  }
  TcpListener listener;
  listener.handle_ = from_socket(handle);
  listener.port_ = ::ntohs(bound.sin_port);
  return listener;
}

Result<TcpSocket> TcpListener::accept() {
  if (!valid()) return make_error(ErrorCode::kIo, "listener is closed");
  sockaddr_in peer{};
#ifdef _WIN32
  int peer_size = sizeof(peer);
#else
  socklen_t peer_size = sizeof(peer);
#endif
  SocketHandle handle = ::accept(to_socket(handle_), reinterpret_cast<sockaddr*>(&peer), &peer_size);
  if (!socket_valid(handle)) {
    return make_error(ErrorCode::kIo, "accept failed: " + last_socket_error());
  }
  int no_delay = 1;
  ::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&no_delay),
               sizeof(no_delay));
  return TcpSocket::adopt(from_socket(handle));
}

Result<TcpSocket> connect_loopback(std::uint16_t port) {
  Status ready = transport_init();
  if (!ready) return ready.error();
  SocketHandle handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (!socket_valid(handle)) {
    return make_error(ErrorCode::kIo, "socket creation failed: " + last_socket_error());
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  address.sin_port = ::htons(port);
  if (::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close_socket(handle);
    return make_error(ErrorCode::kIo, "connect failed: " + last_socket_error());
  }
  int no_delay = 1;
  ::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&no_delay),
               sizeof(no_delay));
  return TcpSocket::adopt(from_socket(handle));
}

}  // namespace brf
