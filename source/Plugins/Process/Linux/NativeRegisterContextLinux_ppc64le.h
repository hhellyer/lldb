//===-- NativeRegisterContextLinux_ppc64le.h ---------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// This implementation is related to the OpenPOWER ABI for Power Architecture
// 64-bit ELF V2 ABI

#if defined(__powerpc64__)

#ifndef lldb_NativeRegisterContextLinux_powerpc_h
#define lldb_NativeRegisterContextLinux_powerpc_h

#include <elf.h>
#include "Plugins/Process/Linux/NativeRegisterContextLinux.h"
#include "Plugins/Process/Utility/lldb-ppc64le-register-enums.h"

namespace lldb_private {
namespace process_linux {

class NativeProcessLinux;

class NativeRegisterContextLinux_ppc64le : public NativeRegisterContextLinux {
public:
  NativeRegisterContextLinux_ppc64le(const ArchSpec &target_arch,
                                   NativeThreadProtocol &native_thread,
                                   uint32_t concrete_frame_idx);

  uint32_t GetRegisterSetCount() const override;

  uint32_t GetUserRegisterCount() const override;

  const RegisterSet *GetRegisterSet(uint32_t set_index) const override;

  Status ReadRegister(const RegisterInfo *reg_info,
                      RegisterValue &reg_value) override;

  Status WriteRegister(const RegisterInfo *reg_info,
                       const RegisterValue &reg_value) override;

  Status ReadAllRegisterValues(lldb::DataBufferSP &data_sp) override;

  Status WriteAllRegisterValues(const lldb::DataBufferSP &data_sp) override;

  //------------------------------------------------------------------
  // Hardware breakpoints/watchpoint mangement functions
  //------------------------------------------------------------------

  uint32_t NumSupportedHardwareBreakpoints() override;

  uint32_t SetHardwareBreakpoint(lldb::addr_t addr, size_t size) override;

  bool ClearHardwareBreakpoint(uint32_t hw_idx) override;

  Status ClearAllHardwareBreakpoints() override;

  Status GetHardwareBreakHitIndex(uint32_t &bp_index,
                                  lldb::addr_t trap_addr) override;

  uint32_t NumSupportedHardwareWatchpoints() override;

  uint32_t SetHardwareWatchpoint(lldb::addr_t addr, size_t size,
                                 uint32_t watch_flags) override;

  bool ClearHardwareWatchpoint(uint32_t hw_index) override;

  Status ClearAllHardwareWatchpoints() override;

  Status GetWatchpointHitIndex(uint32_t &wp_index,
                               lldb::addr_t trap_addr) override;

  lldb::addr_t GetWatchpointHitAddress(uint32_t wp_index) override;

  lldb::addr_t GetWatchpointAddress(uint32_t wp_index) override;

  uint32_t GetWatchpointSize(uint32_t wp_index);

  bool WatchpointIsEnabled(uint32_t wp_index);

  // Debug register type select
  enum DREGType { eDREGTypeWATCH = 0, eDREGTypeBREAK };

protected:
  Status DoReadGPR(void *buf, size_t buf_size) override;

  Status DoWriteGPR(void *buf, size_t buf_size) override;

  Status DoReadFPR(void *buf, size_t buf_size) override;

  Status DoWriteFPR(void *buf, size_t buf_size) override;

  Status DoReadVMX(void *buf, size_t buf_size);

  Status DoWriteVMX(void *buf, size_t buf_size);

  Status DoReadVSX(void *buf, size_t buf_size);

  Status DoWriteVSX(void *buf, size_t buf_size);

  bool IsVMX(unsigned reg);

  bool IsVSX(unsigned reg);

  Status ReadVMX();

  Status WriteVMX();

  Status ReadVSX();

  Status WriteVSX();

  void *GetGPRBuffer() override { return &m_gpr_ppc64le; }

  void *GetFPRBuffer() override { return &m_fpr_ppc64le; }

  void *GetVMXBuffer() { return &m_vmx_ppc64le; }

  void *GetVSXBuffer() { return &m_vsx_ppc64le; }

  size_t GetFPRSize() override { return sizeof(m_fpr_ppc64le); }

  size_t GetVMXSize() { return sizeof(m_vmx_ppc64le); }

  size_t GetVSXSize() { return sizeof(m_vsx_ppc64le); }

private:
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
    Reg pad;
    Reg vscr;
    uint32_t vrsave;
  };

  struct VSX {
    Reg v[32];
  };

  RegInfo m_reg_info;
  Reg m_gpr_ppc64le[ELF_NGREG]; // 64-bit general purpose registers.
  FPU m_fpr_ppc64le; // floating-point registers including extended register.
  VMX m_vmx_ppc64le; // VMX registers.
  VSX m_vsx_ppc64le; // Last lower bytes from first VSX registers.

  // Debug register info for hardware breakpoints and watchpoints management.
  struct DREG {
    lldb::addr_t address;  // Breakpoint/watchpoint address value.
    lldb::addr_t hit_addr; // Address at which last watchpoint trigger exception
                           // occurred.
    lldb::addr_t real_addr; // Address value that should cause target to stop.
    uint32_t control;       // Breakpoint/watchpoint control value.
    uint32_t refcount;      // Serves as enable/disable and refernce counter.
  };

  struct DREG m_hbr_regs[1];
  struct DREG m_hwp_regs[1];

  uint32_t m_max_hwp_supported;
  uint32_t m_max_hbp_supported;
  bool m_refresh_hwdebug_info;

  bool IsGPR(unsigned reg) const;

  bool IsFPR(unsigned reg) const;

  bool IsVMX(unsigned reg) const;

  bool IsVSX(unsigned reg) const;

  Status ReadHardwareDebugInfo();

  Status WriteHardwareDebugRegs(int hwbType);

  uint32_t CalculateFprOffset(const RegisterInfo *reg_info) const;

  uint32_t CalculateVmxOffset(const RegisterInfo *reg_info) const;

  uint32_t CalculateVsxOffset(const RegisterInfo *reg_info) const;
};

} // namespace process_linux
} // namespace lldb_private

#endif // #ifndef lldb_NativeRegisterContextLinux_powerpc_h

#endif // defined(__powerpc64__)
