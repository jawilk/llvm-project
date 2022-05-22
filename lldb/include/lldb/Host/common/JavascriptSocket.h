//===-- JavascriptSocket.h ------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_HOST_JAVASCRIPTSOCKET_H
#define LLDB_HOST_JAVASCRIPTSOCKET_H

#include "lldb/Host/Socket.h"
#include "lldb/Host/SocketAddress.h"
#include <map>

namespace lldb_private {
class JavascriptSocket : public Socket {
public:
  JavascriptSocket(bool should_close, bool child_processes_inherit);
  ~JavascriptSocket() override;

  Status Connect(llvm::StringRef name) override;
  Status Listen(llvm::StringRef name, int backlog) override;
  Status Accept(Socket *&conn_socket) override;

  Status CreateSocket(int domain);

  bool IsValid() const override;
};
}

#endif // LLDB_HOST_JAVASCRIPTSOCKET_H
