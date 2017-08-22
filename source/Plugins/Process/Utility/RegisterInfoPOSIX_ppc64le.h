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
  // based on RegisterContextDarwin_ppc64le.h
  struct GPR {
    uint64_t x[32]; // x0-x32
    uint64_t fp;    // x29
    uint64_t lr;    // x30
    uint64_t sp;    // x31
    uint64_t pc;    // pc
    uint32_t cpsr;  // cpsr
  };

  // based on RegisterContextDarwin_ppc64le.h
  struct VReg {
    uint8_t bytes[16];
  };

  // based on RegisterContextDarwin_ppc64le.h
  struct FPU {
    VReg v[32];
    uint64_t fpscr;
  };

  // based on RegisterContextDarwin_ppc64le.h
  struct EXC {
    uint64_t far;       // Virtual Fault Address
    uint32_t esr;       // Exception syndrome
    uint32_t exception; // number of arm exception token
  };

  // based on RegisterContextDarwin_ppc64le.h
  struct DBG {
    uint64_t bvr[16];
    uint64_t bcr[16];
    uint64_t wvr[16];
    uint64_t wcr[16];
    uint64_t mdscr_el1;
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
