//===-- RegisterInfoPOSIX_ppc64le.h -------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_RegisterContextLinux_ppc64le_H_
#define liblldb_RegisterContextLinux_ppc64le_H_

#include "RegisterInfoInterface.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/lldb-private.h"

class RegisterInfoPOSIX_ppc64le : public lldb_private::RegisterInfoInterface {
public:
  struct GPR {
    uint64_t r[32]; // r0-r32
    uint64_t lr;
    uint64_t cr;
    uint64_t ctr;
    uint64_t xer;
  };

  struct VReg {
    uint8_t bytes[16];
  };

  struct FPU {
    VReg v[32];
    uint32_t fpsr;
    uint32_t fpcr;
  };

  RegisterInfoPOSIX_ppc64le(const lldb_private::ArchSpec &target_arch);

  size_t GetGPRSize() const override;

  const lldb_private::RegisterInfo *GetRegisterInfo() const override;

  uint32_t GetRegisterCount() const override;

private:
  const lldb_private::RegisterInfo *m_register_info_p;
  uint32_t m_register_info_count;
};

#endif
