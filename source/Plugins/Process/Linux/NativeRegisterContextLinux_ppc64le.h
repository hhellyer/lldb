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

#ifndef lldb_NativeRegisterContextLinux_ppc64le_h
#define lldb_NativeRegisterContextLinux_ppc64le_h

#include "Plugins/Process/Linux/NativeRegisterContextLinux.h"
#include "Plugins/Process/Utility/lldb-ppc64le-register-enums.h"

#define DECLARE_REGISTER_INFOS_PPC64LE_STRUCT
#include "RegisterInfos_ppc64le.h"
#undef DECLARE_REGISTER_INFOS_PPC64LE_STRUCT

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
  GPR m_gpr_ppc64le; // 64-bit general purpose registers.
  FPR m_fpr_ppc64le; // floating-point registers including extended register.
  VMX m_vmx_ppc64le; // VMX registers.
  VSX m_vsx_ppc64le; // Last lower bytes from first VSX registers.

  bool IsGPR(unsigned reg) const;

  bool IsFPR(unsigned reg) const;

  bool IsVMX(unsigned reg) const;

  bool IsVSX(unsigned reg) const;

  uint32_t CalculateFprOffset(const RegisterInfo *reg_info) const;

  uint32_t CalculateVmxOffset(const RegisterInfo *reg_info) const;

  uint32_t CalculateVsxOffset(const RegisterInfo *reg_info) const;
};

} // namespace process_linux
} // namespace lldb_private

#endif // #ifndef lldb_NativeRegisterContextLinux_ppc64le_h

#endif // defined(__powerpc64__)
