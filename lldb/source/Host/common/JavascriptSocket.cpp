//===-- Socket.cpp --------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Host/JavascriptSocket.h"

#include "lldb/Host/Config.h"
#include "lldb/Host/Host.h"
#include "lldb/Host/SocketAddress.h"
#include "lldb/Host/StringConvert.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegularExpression.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/WindowsError.h"

#if LLDB_ENABLE_POSIX
#include "lldb/Host/posix/DomainSocket.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

using namespace lldb;
using namespace lldb_private;

typedef const void *set_socket_option_arg_type;
typedef void *get_socket_option_arg_type;
const NativeSocket Socket::kInvalidSocketValue = -1;

namespace {

bool IsInterrupted() {
  return errno == EINTR;
}
}

JavascriptSocket::JavascriptSocket()
    : IOObject(eFDTypeSocket) {}

JavascriptSocket::~JavascriptSocket() { Close(); }

llvm::Error JavascriptSocket::Initialize() {

  return llvm::Error::success();
}

void JavascriptSocket::Terminate() {
}

std::unique_ptr<Socket> JavascriptSocket::Create(Status &error) {
  error.Clear();

  std::unique_ptr<JavascriptSocket> socket_up = std::make_unique<JavascriptSocket>();

  if (error.Fail())
    socket_up.reset();

  return socket_up;
}

llvm::Expected<std::unique_ptr<JavascriptSocket>>
JavascriptSocket::Connect(llvm::StringRef host_and_port) {
  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_CONNECTION));
  LLDB_LOG(log, "host_and_port = {0}", host_and_port);

  Status error;
  std::unique_ptr<JavascriptSocket> connect_socket(
      Create(error));
  if (error.Fail())
    return error.ToError();

  error = connect_socket->Connect(host_and_port);
  if (error.Success())
    return std::move(connect_socket);

  return error.ToError();
}

bool Socket::DecodeHostAndPort(llvm::StringRef host_and_port,
                               std::string &host_str, std::string &port_str,
                               int32_t &port, Status *error_ptr) {
  static RegularExpression g_regex(
      llvm::StringRef("([^:]+|\\[[0-9a-fA-F:]+.*\\]):([0-9]+)"));
  llvm::SmallVector<llvm::StringRef, 3> matches;
  if (g_regex.Execute(host_and_port, &matches)) {
    host_str = matches[1].str();
    port_str = matches[2].str();
    // IPv6 addresses are wrapped in [] when specified with ports
    if (host_str.front() == '[' && host_str.back() == ']')
      host_str = host_str.substr(1, host_str.size() - 2);
    bool ok = false;
    port = StringConvert::ToUInt32(port_str.c_str(), UINT32_MAX, 10, &ok);
    if (ok && port <= UINT16_MAX) {
      if (error_ptr)
        error_ptr->Clear();
      return true;
    }
    // port is too large
    if (error_ptr)
      error_ptr->SetErrorStringWithFormat(
          "invalid host:port specification: '%s'", host_and_port.str().c_str());
    return false;
  }

  // If this was unsuccessful, then check if it's simply a signed 32-bit
  // integer, representing a port with an empty host.
  host_str.clear();
  port_str.clear();
  if (to_integer(host_and_port, port, 10) && port < UINT16_MAX) {
    port_str = std::string(host_and_port);
    if (error_ptr)
      error_ptr->Clear();
    return true;
  }

  if (error_ptr)
    error_ptr->SetErrorStringWithFormat("invalid host:port specification: '%s'",
                                        host_and_port.str().c_str());
  return false;
}

IOObject::WaitableHandle JavascriptSocket::GetWaitableHandle() {
  return m_socket;
}

Status JavascriptSocket::Read(void *buf, size_t &num_bytes) {
  Status error;
  int bytes_received = 0;
  do {
    bytes_received = ::recv(m_socket, static_cast<char *>(buf), num_bytes, 0);
  } while (bytes_received < 0 && IsInterrupted());

  if (bytes_received < 0) {
    SetLastError(error);
    num_bytes = 0;
  } else
    num_bytes = bytes_received;

  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_COMMUNICATION));
  if (log) {
    LLDB_LOGF(log,
              "%p Socket::Read() (socket = %" PRIu64
              ", src = %p, src_len = %" PRIu64 ", flags = 0) => %" PRIi64
              " (error = %s)",
              static_cast<void *>(this), static_cast<uint64_t>(m_socket), buf,
              static_cast<uint64_t>(num_bytes),
              static_cast<int64_t>(bytes_received), error.AsCString());
  }

  return error;
}

Status JavascriptSocket::Write(const void *buf, size_t &num_bytes) {
  const size_t src_len = num_bytes;
  Status error;
  int bytes_sent = 0;
  do {
    bytes_sent = Send(buf, num_bytes);
  } while (bytes_sent < 0 && IsInterrupted());

  if (bytes_sent < 0) {
    SetLastError(error);
    num_bytes = 0;
  } else
    num_bytes = bytes_sent;

  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_COMMUNICATION));
  if (log) {
    LLDB_LOGF(log,
              "%p Socket::Write() (socket = %" PRIu64
              ", src = %p, src_len = %" PRIu64 ", flags = 0) => %" PRIi64
              " (error = %s)",
              static_cast<void *>(this), static_cast<uint64_t>(m_socket), buf,
              static_cast<uint64_t>(src_len),
              static_cast<int64_t>(bytes_sent), error.AsCString());
  }

  return error;
}

Status JavascriptSocket::PreDisconnect() {
  Status error;
  return error;
}

Status JavascriptSocket::Close() {
  Status error;
  if (!IsValid() || !m_should_close_fd)
    return error;

  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_CONNECTION));
  LLDB_LOGF(log, "%p Socket::Close (fd = %" PRIu64 ")",
            static_cast<void *>(this), static_cast<uint64_t>(m_socket));

#if defined(_WIN32)
  bool success = !!closesocket(m_socket);
#else
  bool success = !!::close(m_socket);
#endif
  // A reference to a FD was passed in, set it to an invalid value
  m_socket = kInvalidSocketValue;
  if (!success) {
    SetLastError(error);
  }

  return error;
}

int JavascriptSocket::GetOption(int level, int option_name, int &option_value) {
  get_socket_option_arg_type option_value_p =
      reinterpret_cast<get_socket_option_arg_type>(&option_value);
  socklen_t option_value_size = sizeof(int);
  return ::getsockopt(m_socket, level, option_name, option_value_p,
                      &option_value_size);
}

int JavascriptSocket::SetOption(int level, int option_name, int option_value) {
  set_socket_option_arg_type option_value_p =
      reinterpret_cast<get_socket_option_arg_type>(&option_value);
  return ::setsockopt(m_socket, level, option_name, option_value_p,
                      sizeof(option_value));
}

size_t JavascriptSocket::Send(const void *buf, const size_t num_bytes) {
  return ::send(m_socket, static_cast<const char *>(buf), num_bytes, 0);
}

void JavascriptSocket::SetLastError(Status &error) {
  error.SetErrorToErrno();
}
