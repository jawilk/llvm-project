//===-- Socket.cpp --------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__EMSCRIPTEN__)
#include "/home/wj/projects/emsdk/upstream/emscripten/cache/sysroot/include/emscripten/emscripten.h"
#endif

#include "lldb/Host/Socket.h"

#include "lldb/Host/Config.h"
#include "lldb/Host/Host.h"
#include "lldb/Host/SocketAddress.h"
#include "lldb/Host/StringConvert.h"
#include "lldb/Host/common/JavascriptSocket.h"
#include "lldb/Host/common/TCPSocket.h"
#include "lldb/Host/common/UDPSocket.h"
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

#ifdef __linux__
#include "lldb/Host/linux/AbstractSocket.h"
#endif

#ifdef __ANDROID__
#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <cerrno>
#include <fcntl.h>
#include <linux/tcp.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif // __ANDROID__

using namespace lldb;
using namespace lldb_private;

#if defined(_WIN32)
typedef const char *set_socket_option_arg_type;
typedef char *get_socket_option_arg_type;
const NativeSocket Socket::kInvalidSocketValue = INVALID_SOCKET;
#else  // #if defined(_WIN32)
typedef const void *set_socket_option_arg_type;
typedef void *get_socket_option_arg_type;
const NativeSocket Socket::kInvalidSocketValue = -1;
#endif // #if defined(_WIN32)

namespace {

bool IsInterrupted() {
#if defined(_WIN32)
  return ::WSAGetLastError() == WSAEINTR;
#else
  return errno == EINTR;
#endif
}
}

Socket::Socket(SocketProtocol protocol, bool should_close,
               bool child_processes_inherit)
    : IOObject(eFDTypeSocket), m_protocol(protocol),
      m_socket(kInvalidSocketValue),
      m_child_processes_inherit(child_processes_inherit),
      m_should_close_fd(should_close) {}

Socket::~Socket() { Close(); }

llvm::Error Socket::Initialize() {
#if defined(_WIN32)
  auto wVersion = WINSOCK_VERSION;
  WSADATA wsaData;
  int err = ::WSAStartup(wVersion, &wsaData);
  if (err == 0) {
    if (wsaData.wVersion < wVersion) {
      WSACleanup();
      return llvm::make_error<llvm::StringError>(
          "WSASock version is not expected.", llvm::inconvertibleErrorCode());
    }
  } else {
    return llvm::errorCodeToError(llvm::mapWindowsError(::WSAGetLastError()));
  }
#endif

  return llvm::Error::success();
}

void Socket::Terminate() {
#if defined(_WIN32)
  ::WSACleanup();
#endif
}

std::unique_ptr<Socket> Socket::Create(const SocketProtocol protocol,
                                       bool child_processes_inherit,
                                       Status &error) {
  llvm::errs() << "Socket::Create\n";
  error.Clear();

  std::unique_ptr<Socket> socket_up;
  switch (protocol) {
  case ProtocolJavascript:
    socket_up =
        std::make_unique<JavascriptSocket>(true, child_processes_inherit);
    break;
  case ProtocolTcp:
    socket_up =
        std::make_unique<TCPSocket>(true, child_processes_inherit);
    break;
  case ProtocolUdp:
    socket_up =
        std::make_unique<UDPSocket>(true, child_processes_inherit);
    break;
  case ProtocolUnixDomain:
#if LLDB_ENABLE_POSIX
    socket_up =
        std::make_unique<DomainSocket>(true, child_processes_inherit);
#else
    error.SetErrorString(
        "Unix domain sockets are not supported on this platform.");
#endif
    break;
  case ProtocolUnixAbstract:
#ifdef __linux__
    socket_up =
        std::make_unique<AbstractSocket>(child_processes_inherit);
#else
    error.SetErrorString(
        "Abstract domain sockets are not supported on this platform.");
#endif
    break;
  }

  if (error.Fail())
    socket_up.reset();

  return socket_up;
}

// EMSCRIPTEN
llvm::Expected<std::unique_ptr<Socket>> Socket::JavascriptConnect() {
  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_CONNECTION));
  LLDB_LOG(log, "host_and_port = {0}", "javascript");

  Status error;
  std::unique_ptr<Socket> connect_socket(
      Create(ProtocolJavascript, false, error));
  if (error.Fail())
    return error.ToError();

  error = connect_socket->Connect("");
  if (error.Success())
    return std::move(connect_socket);

  return error.ToError();
}


llvm::Expected<std::unique_ptr<Socket>>
Socket::TcpConnect(llvm::StringRef host_and_port,
                   bool child_processes_inherit) {
  llvm::errs() << "Socket::TcpConnect\n";
  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_CONNECTION));
  LLDB_LOG(log, "host_and_port = {0}", host_and_port);

  Status error;
  std::unique_ptr<Socket> connect_socket(
      Create(ProtocolTcp, child_processes_inherit, error));
  llvm::errs() << "After Create - Socket::TcpConnect\n";
  if (error.Fail())
    return error.ToError();

  error = connect_socket->Connect(host_and_port);
  if (error.Success())
    return std::move(connect_socket);
  llvm::errs() << "ERROR Socket::TcpConnect\n";
  return error.ToError();
}

llvm::Expected<std::unique_ptr<TCPSocket>>
Socket::TcpListen(llvm::StringRef host_and_port, bool child_processes_inherit,
                  Predicate<uint16_t> *predicate, int backlog) {
  llvm::errs() << "Socket::TcpListen\ņ";
  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_CONNECTION));
  LLDB_LOG(log, "host_and_port = {0}", host_and_port);

  Status error;
  std::string host_str;
  std::string port_str;
  int32_t port = INT32_MIN;
  if (!DecodeHostAndPort(host_and_port, host_str, port_str, port, &error))
    return error.ToError();

  std::unique_ptr<TCPSocket> listen_socket(
      new TCPSocket(true, child_processes_inherit));

  error = listen_socket->Listen(host_and_port, backlog);
  if (error.Fail())
    return error.ToError();

  // We were asked to listen on port zero which means we must now read the
  // actual port that was given to us as port zero is a special code for
  // "find an open port for me".
  if (port == 0)
    port = listen_socket->GetLocalPortNumber();

  // Set the port predicate since when doing a listen://<host>:<port> it
  // often needs to accept the incoming connection which is a blocking system
  // call. Allowing access to the bound port using a predicate allows us to
  // wait for the port predicate to be set to a non-zero value from another
  // thread in an efficient manor.
  if (predicate)
    predicate->SetValue(port, eBroadcastAlways);
  return std::move(listen_socket);
}

llvm::Expected<std::unique_ptr<UDPSocket>>
Socket::UdpConnect(llvm::StringRef host_and_port,
                   bool child_processes_inherit) {
  return UDPSocket::Connect(host_and_port, child_processes_inherit);
}

Status Socket::UnixDomainConnect(llvm::StringRef name,
                                 bool child_processes_inherit,
                                 Socket *&socket) {
  Status error;
  std::unique_ptr<Socket> connect_socket(
      Create(ProtocolUnixDomain, child_processes_inherit, error));
  if (error.Fail())
    return error;

  error = connect_socket->Connect(name);
  if (error.Success())
    socket = connect_socket.release();

  return error;
}

Status Socket::UnixDomainAccept(llvm::StringRef name,
                                bool child_processes_inherit, Socket *&socket) {
  Status error;
  std::unique_ptr<Socket> listen_socket(
      Create(ProtocolUnixDomain, child_processes_inherit, error));
  if (error.Fail())
    return error;

  error = listen_socket->Listen(name, 5);
  if (error.Fail())
    return error;

  error = listen_socket->Accept(socket);
  return error;
}

Status Socket::UnixAbstractConnect(llvm::StringRef name,
                                   bool child_processes_inherit,
                                   Socket *&socket) {
  Status error;
  std::unique_ptr<Socket> connect_socket(
      Create(ProtocolUnixAbstract, child_processes_inherit, error));
  if (error.Fail())
    return error;

  error = connect_socket->Connect(name);
  if (error.Success())
    socket = connect_socket.release();
  return error;
}

Status Socket::UnixAbstractAccept(llvm::StringRef name,
                                  bool child_processes_inherit,
                                  Socket *&socket) {
  Status error;
  std::unique_ptr<Socket> listen_socket(
      Create(ProtocolUnixAbstract, child_processes_inherit, error));
  if (error.Fail())
    return error;

  error = listen_socket->Listen(name, 5);
  if (error.Fail())
    return error;

  error = listen_socket->Accept(socket);
  return error;
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

IOObject::WaitableHandle Socket::GetWaitableHandle() {
  // TODO: On Windows, use WSAEventSelect
  llvm::errs() << "Socket::GetWaitableHandle\ņ";
  return m_socket;
}

/*#if defined(__EMSCRIPTEN__)
uint8_t rbpf_data[8192];
extern "C" {
    void get_rbpf_data(const char *data, const size_t num_bytes) {
        llvm::errs() << "get_rbpf_buf\n";
        for (int i=0; i<num_bytes; i++)
            rbpf_data[i] = data[i];
    }
}
#endif*/
Status Socket::Read(void *buf, size_t &num_bytes) {
  llvm::errs() << "Socket::Read (REAL READ)\n";
  llvm::errs() << "m_socket: " << m_socket << "\n";
  Status error;

  /*#if defined(__EMSCRIPTEN__)
  num_bytes = EM_ASM_INT({
      return get_lldb_buf();
  }, num_bytes);
  memcpy(buf, rbpf_data, num_bytes);
  for (int i=0; i<num_bytes; i++)
    llvm::errs() << ((char*) buf)[i];
  llvm::errs() << "\n";
  #else*/
  int bytes_received = 0;
  do {
    bytes_received = ::recv(3, static_cast<char *>(buf), num_bytes, 0);
    emscripten_sleep(100);
  } while (bytes_received < 0 && IsInterrupted());

  if (bytes_received < 0) {
    SetLastError(error);
    num_bytes = 0;
  } else
    num_bytes = bytes_received;

  llvm::errs() << "num_bytes: " << num_bytes << "\n";
  if (num_bytes > 0) {
    for (int i=0; i<num_bytes; i++)
      llvm::errs() << ((char*) buf)[i];
    llvm::errs() << "\n";
  }

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
  //#endif
  llvm::errs() << "END Socket::Read error type: " << error.AsCString() << "\n";
  return error;
}

Status Socket::Write(const void *buf, size_t &num_bytes) {
  llvm::errs() << "Socket::Write 2 args\n";
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

Status Socket::PreDisconnect() {
  Status error;
  return error;
}

Status Socket::Close() {
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

int Socket::GetOption(int level, int option_name, int &option_value) {
  get_socket_option_arg_type option_value_p =
      reinterpret_cast<get_socket_option_arg_type>(&option_value);
  socklen_t option_value_size = sizeof(int);
  return ::getsockopt(m_socket, level, option_name, option_value_p,
                      &option_value_size);
}

int Socket::SetOption(int level, int option_name, int option_value) {
  set_socket_option_arg_type option_value_p =
      reinterpret_cast<get_socket_option_arg_type>(&option_value);
  return ::setsockopt(m_socket, level, option_name, option_value_p,
                      sizeof(option_value));
}

/*#if defined(__EMSCRIPTEN__)
extern "C" {
    char* set_rbpf_buf(char *data, int num_bytes) {
    llvm::errs() << "set_rbpf_buf\n";
    for (int i=0; i<num_bytes; i++)
      llvm::errs() << data[i];
    return data;
    }
}
#endif*/

size_t Socket::Send(const void *buf, const size_t num_bytes) {
  llvm::errs() << "Socket::Send (REAL SEND) len: " << num_bytes << " payload: ";
  for (int i=0; i<num_bytes; i++)
      llvm::errs() << ((char*) buf)[i];
  llvm::errs() << "\n";
  /*#if defined(__EMSCRIPTEN__)
  EM_ASM({
      var reply = Module.ccall('set_rbpf_buf', 'string', ['number', 'number'], [$1, $0]);
      console.log("REPLY lldb");
      console.log(reply);
      lldb_reply[call_count] = reply;
      //rbpf_buf_len = $0;
      //rbpf_buf = Module._malloc($0);
      //Module.ccall('set_rbpf_buf', ['number', 'number', 'number'], [rbpf_buf, $1, $0]);
      }, num_bytes, static_cast<const char *>(buf));
  return num_bytes;*/
  //#else
  return ::send(3, static_cast<const char *>(buf), num_bytes, 0);
  //#endif
}

void Socket::SetLastError(Status &error) {
#if defined(_WIN32)
  error.SetError(::WSAGetLastError(), lldb::eErrorTypeWin32);
#else
  error.SetErrorToErrno();
#endif
}

NativeSocket Socket::CreateSocket(const int domain, const int type,
                                  const int protocol,
                                  bool child_processes_inherit, Status &error) {
  llvm::errs() << "Socket::CreateSocket\n";
  error.Clear();
  auto socket_type = type;
#ifdef SOCK_CLOEXEC
  if (!child_processes_inherit)
    socket_type |= SOCK_CLOEXEC;
#endif
  auto sock = ::socket(domain, socket_type, protocol);
  llvm::errs() << "sock: " << sock << "\n";
  if (sock == kInvalidSocketValue)
    SetLastError(error);

  return sock;
}

NativeSocket Socket::AcceptSocket(NativeSocket sockfd, struct sockaddr *addr,
                                  socklen_t *addrlen,
                                  bool child_processes_inherit, Status &error) {
  error.Clear();
#if defined(ANDROID_USE_ACCEPT_WORKAROUND)
  // Hack:
  // This enables static linking lldb-server to an API 21 libc, but still
  // having it run on older devices. It is necessary because API 21 libc's
  // implementation of accept() uses the accept4 syscall(), which is not
  // available in older kernels. Using an older libc would fix this issue, but
  // introduce other ones, as the old libraries were quite buggy.
  int fd = syscall(__NR_accept, sockfd, addr, addrlen);
  if (fd >= 0 && !child_processes_inherit) {
    int flags = ::fcntl(fd, F_GETFD);
    if (flags != -1 && ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1)
      return fd;
    SetLastError(error);
    close(fd);
  }
  return fd;
#elif defined(SOCK_CLOEXEC) && defined(HAVE_ACCEPT4)
  int flags = 0;
  if (!child_processes_inherit) {
    flags |= SOCK_CLOEXEC;
  }
  NativeSocket fd = llvm::sys::RetryAfterSignal(
      static_cast<NativeSocket>(-1), ::accept4, sockfd, addr, addrlen, flags);
#else
  NativeSocket fd = llvm::sys::RetryAfterSignal(
      static_cast<NativeSocket>(-1), ::accept, sockfd, addr, addrlen);
#endif
  if (fd == kInvalidSocketValue)
    SetLastError(error);
  return fd;
}
