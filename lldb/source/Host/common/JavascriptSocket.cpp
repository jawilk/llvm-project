//===-- JavascriptSocket.cpp --------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(_MSC_VER)
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include "lldb/Host/common/JavascriptSocket.h"

#include "lldb/Host/Config.h"
#include "lldb/Host/MainLoop.h"
#include "lldb/Utility/Log.h"

#include "llvm/Config/llvm-config.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/WindowsError.h"
#include "llvm/Support/raw_ostream.h"

#if LLDB_ENABLE_POSIX
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#if defined(_WIN32)
#include <winsock2.h>
#endif

#ifdef _WIN32
#define CLOSE_SOCKET closesocket
typedef const char *set_socket_option_arg_type;
#else
#include <unistd.h>
#define CLOSE_SOCKET ::close
typedef const void *set_socket_option_arg_type;
#endif

using namespace lldb;
using namespace lldb_private;

static Status GetLastSocketError() {
  std::error_code EC;
#ifdef _WIN32
  EC = llvm::mapWindowsError(WSAGetLastError());
#else
  EC = std::error_code(errno, std::generic_category());
#endif
  return EC;
}

namespace {
const int kType = SOCK_STREAM;
}
JavascriptSocket::JavascriptSocket(bool should_close, bool child_processes_inherit)
    : Socket(ProtocolJavascript, should_close, child_processes_inherit) {}
JavascriptSocket::~JavascriptSocket() { }

bool JavascriptSocket::IsValid() const {
  //llvm::errs() << "JavascriptSocket::" << __FUNCTION__ << "\n";
  return true;
}

Status JavascriptSocket::CreateSocket(int domain) {
  llvm::errs() << "JavascriptSocket::" << __FUNCTION__ << "\n";
  Status error;
  if (IsValid())
    error = Close();
  if (error.Fail())
    return error;
  m_socket = 1;/*Socket::CreateSocket(domain, kType, IPPROTO_TCP,
                                  m_child_processes_inherit, error);*/
  return error;
}

Status JavascriptSocket::Connect(llvm::StringRef name) {
  llvm::errs() << "JavascriptSocket::Connect\n"; 

  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_COMMUNICATION));
  LLDB_LOGF(log, "JavascriptSocket::%s (host/port = %s)", __FUNCTION__, "javascript");

  Status error;
  error = CreateSocket(0);
  error.Clear();
  return error;
}

Status JavascriptSocket::Listen(llvm::StringRef name, int backlog) {
  llvm::errs() << "JavascriptSocket::" << __FUNCTION__ << "\n";
  Log *log(lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_CONNECTION));
  LLDB_LOGF(log, "JavascriptSocket::%s (%s)", __FUNCTION__, name.data());
  
  return Status();
}

Status JavascriptSocket::Accept(Socket *&conn_socket) {
  llvm::errs() << "JavascriptSocket::" << __FUNCTION__ << "\n";
  Status error;
  
  error.Clear();
  return error;
}
