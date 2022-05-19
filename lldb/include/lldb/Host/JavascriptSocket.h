//===-- JavascriptSocket.h ------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_HOST_JAVASCRIPTSOCKET_H
#define LLDB_HOST_JAVASCRIPTSOCKET_H

#include <memory>
#include <string>

#include "lldb/lldb-private.h"

#include "lldb/Host/SocketAddress.h"
#include "lldb/Utility/IOObject.h"
#include "lldb/Utility/Predicate.h"
#include "lldb/Utility/Status.h"

namespace llvm {
class StringRef;
}

namespace lldb_private {

class JavascriptSocket : public IOObject {
public:

  ~JavascriptSocket() override;

  static llvm::Error Initialize();
  static void Terminate();

  static std::unique_ptr<JavascriptSocket> Create(Status &error);

  virtual Status Connect(llvm::StringRef name) = 0;

  int GetOption(int level, int option_name, int &option_value);
  int SetOption(int level, int option_name, int option_value);


  Status Read(void *buf, size_t &num_bytes) override;
  Status Write(const void *buf, size_t &num_bytes) override;

  virtual Status PreDisconnect();
  Status Close() override;

  bool IsValid() const override { return true; }
  WaitableHandle GetWaitableHandle() override;

  // If this Socket is connected then return the URI used to connect.
  virtual std::string GetRemoteConnectionURI() const { return ""; };

protected:
  JavascriptSocket();

  virtual size_t Send(const void *buf, const size_t num_bytes);

  static void SetLastError(Status &error);
};

} // namespace lldb_private

#endif // LLDB_HOST_JAVASCRIPTSOCKET_H
