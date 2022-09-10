//===-- VSCode.cpp ----------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <chrono>
#include <cstdarg>
#include <fstream>
#include <mutex>
#include <sstream>

#include "LLDBUtils.h"
#include "VSCode.h"
#include "llvm/Support/FormatVariadic.h"

using namespace lldb_vscode;

namespace lldb_vscode {

VSCode g_vsc;

VSCode::VSCode()
    : focus_tid(LLDB_INVALID_THREAD_ID), sent_terminated_event(false),
      stop_at_entry(true), is_attach(false), reverse_request_seq(0) {}

VSCode::~VSCode() {}

int64_t VSCode::GetLineForPC(int64_t sourceReference, lldb::addr_t pc) const {
  auto pos = source_map.find(sourceReference);
  if (pos != source_map.end())
    return pos->second.GetLineForPC(pc);
  return 0;
}

int64_t VSCode::GetNextSourceReference() {
  static int64_t ref = 0;
  return ++ref;
}

lldb::SBThread VSCode::GetLLDBThread(const llvm::json::Object &arguments) {
  auto tid = GetSigned(arguments, "threadId", LLDB_INVALID_THREAD_ID);
  return target.GetProcess().GetThreadByID(tid);
}

lldb::SBFrame VSCode::GetLLDBFrame(const llvm::json::Object &arguments) {
  const uint64_t frame_id = GetUnsigned(arguments, "frameId", UINT64_MAX);
  printf("frame_id: %d\n", frame_id);
  lldb::SBProcess process = target.GetProcess();
  return process.GetSelectedThread().GetSelectedFrame();
/*
  // Upper 32 bits is the thread index ID
  lldb::SBThread thread =
      process.GetThreadByIndexID(GetLLDBThreadIndexID(frame_id));
  // Lower 32 bits is the frame index
  return thread.GetFrameAtIndex(GetLLDBFrameID(frame_id));*/
}

llvm::json::Value VSCode::CreateTopLevelScopes() {
  llvm::json::Array scopes;
  scopes.emplace_back(CreateScope("Locals", VARREF_LOCALS,
                                  g_vsc.variables.locals.GetSize(), false));
  scopes.emplace_back(CreateScope("Globals", VARREF_GLOBALS,
                                  g_vsc.variables.globals.GetSize(), false));
  scopes.emplace_back(CreateScope("Registers", VARREF_REGS,
                                  g_vsc.variables.registers.GetSize(), false));
  return llvm::json::Value(std::move(scopes));
}

void VSCode::SetTarget(const lldb::SBTarget target) {
  this->target = target;
}

void Variables::Clear() {
  locals.Clear();
  globals.Clear();
  registers.Clear();
  expandable_variables.clear();
}

int64_t Variables::GetNewVariableRefence(bool is_permanent) {
  if (is_permanent)
    return next_permanent_var_ref++;
  return next_temporary_var_ref++;
}

bool Variables::IsPermanentVariableReference(int64_t var_ref) {
  return var_ref >= PermanentVariableStartIndex;
}

lldb::SBValue Variables::GetVariable(int64_t var_ref) const {
  if (IsPermanentVariableReference(var_ref)) {
    auto pos = expandable_permanent_variables.find(var_ref);
    if (pos != expandable_permanent_variables.end())
      return pos->second;
  } else {
    auto pos = expandable_variables.find(var_ref);
    if (pos != expandable_variables.end())
      return pos->second;
  }
  return lldb::SBValue();
}

int64_t Variables::InsertExpandableVariable(lldb::SBValue variable,
                                            bool is_permanent) {
  int64_t var_ref = GetNewVariableRefence(is_permanent);
  if (is_permanent)
    expandable_permanent_variables.insert(std::make_pair(var_ref, variable));
  else
    expandable_variables.insert(std::make_pair(var_ref, variable));
  return var_ref;
}

} // namespace lldb_vscode
