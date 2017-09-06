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
    uint64_t msr;
    uint64_t origr3;
    uint64_t ctr;
    uint64_t lr;
    uint64_t xer;
    uint64_t cr;
    uint64_t softe;
    uint64_t trap;
    uint64_t dar;
    uint64_t dsisr;
    uint64_t result;
    uint64_t dscr;
    uint64_t pad[4];
  };

  struct VReg {
    uint8_t bytes[8];
  };

  struct VMXReg {
    uint8_t bytes[16];
  };

  struct FPU {
    VReg v[32];
    VReg fpscr;
  };

  struct VMX {
    VMXReg v[32];
    VMXReg vscr;
    VMXReg vrsave;
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
