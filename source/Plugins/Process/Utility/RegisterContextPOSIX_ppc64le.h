//===-- RegisterContextPOSIX_ppc64le.h --------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_RegisterContextPOSIX_powerpc_h_
#define liblldb_RegisterContextPOSIX_powerpc_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include <elf.h>
#include "RegisterInfoInterface.h"
#include "lldb-ppc64le-register-enums.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Utility/Log.h"

class ProcessMonitor;

class RegisterContextPOSIX_ppc64le : public lldb_private::RegisterContext {
public:
  RegisterContextPOSIX_ppc64le(
      lldb_private::Thread &thread, uint32_t concrete_frame_idx,
      lldb_private::RegisterInfoInterface *register_info);

  ~RegisterContextPOSIX_ppc64le() override;

  void Invalidate();

  void InvalidateAllRegisters() override;

  size_t GetRegisterCount() override;

  virtual size_t GetGPRSize();

  virtual unsigned GetRegisterSize(unsigned reg);

  virtual unsigned GetRegisterOffset(unsigned reg);

  const lldb_private::RegisterInfo *GetRegisterInfoAtIndex(size_t reg) override;

  size_t GetRegisterSetCount() override;

  const lldb_private::RegisterSet *GetRegisterSet(size_t set) override;

  const char *GetRegisterName(unsigned reg);

  uint32_t ConvertRegisterKindToRegisterNumber(lldb::RegisterKind kind,
                                               uint32_t num) override;

protected:
  struct RegInfo {
    uint32_t num_registers;
    uint32_t num_gpr_registers;
    uint32_t num_fpr_registers;
    uint32_t num_vmx_registers;
    uint32_t num_vsx_registers;

    uint32_t last_gpr;
    uint32_t first_fpr;
    uint32_t last_fpr;

    uint32_t first_vmx;
    uint32_t last_vmx;

    uint32_t first_vsx;
    uint32_t last_vsx;

    uint32_t gpr_flags;
  };

  struct Reg {
    uint8_t bytes[8];
  };

  struct VReg {
    uint8_t bytes[16];
  };

  struct FPU {
    Reg v[32];
    Reg fpscr;
  };

  struct VMX {
    VReg v[32];
    VReg vscr;
    VReg vrsave;
  };

  struct VSX {
    Reg v[32];
  };

  // 64-bit general purpose registers.
  Reg m_gpr_ppc64le[ELF_NGREG]; // 64-bit general purpose registers.
  FPU m_fpr_ppc64le; // floating-point registers including extended register.
  VMX m_vmx_ppc64le; // VMX registers.
  VSX m_vsx_ppc64le; // VSX registers.

  RegInfo m_reg_info;
  struct RegisterContextPOSIX_ppc64le::FPU
      m_fpr; // floating-point registers including extended register sets.
  std::unique_ptr<lldb_private::RegisterInfoInterface>
      m_register_info_ap; // Register Info Interface (FreeBSD or Linux)

  // Determines if an extended register set is supported on the processor
  // running the inferior process.
  virtual bool IsRegisterSetAvailable(size_t set_index);

  virtual const lldb_private::RegisterInfo *GetRegisterInfo();

  bool IsGPR(unsigned reg);

  bool IsFPR(unsigned reg);

  bool IsVMX(unsigned reg);

  bool IsVSX(unsigned reg);

  lldb::ByteOrder GetByteOrder();

  virtual bool ReadGPR() = 0;
  virtual bool ReadFPR() = 0;
  virtual bool ReadVMX() = 0;
  virtual bool ReadVSX() = 0;
  virtual bool WriteGPR() = 0;
  virtual bool WriteFPR() = 0;
  virtual bool WriteVMX() = 0;
  virtual bool WriteVSX() = 0;
};

#endif // liblldb_RegisterContextPOSIX_powerpc_h_
