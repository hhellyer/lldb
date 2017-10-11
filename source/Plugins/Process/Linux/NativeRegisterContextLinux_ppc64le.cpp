//===-- NativeRegisterContextLinux_ppc64le.cpp ------------------*- C++ -*-===//
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

#include "NativeRegisterContextLinux_ppc64le.h"

#include "lldb/Core/RegisterValue.h"
#include "lldb/Host/common/NativeProcessProtocol.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/Status.h"

#include "Plugins/Process/Linux/NativeProcessLinux.h"
#include "Plugins/Process/Linux/Procfs.h"
#include "Plugins/Process/POSIX/ProcessPOSIXLog.h"
#include "Plugins/Process/Utility/RegisterInfoPOSIX_ppc64le.h"

// System includes - They have to be included after framework includes because
// they define some
// macros which collide with variable names in other modules
#include <sys/socket.h>
#include <elf.h>
#include <asm/ptrace.h>

#define REG_CONTEXT_SIZE (GetGPRSize() + GetFPRSize() \
                          + GetVMXSize() + GetVSXSize())

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_linux;

static const uint32_t g_gpr_regnums_ppc64le[] = {
    gpr_r0_ppc64le,   gpr_r1_ppc64le,  gpr_r2_ppc64le,     gpr_r3_ppc64le,
    gpr_r4_ppc64le,   gpr_r5_ppc64le,  gpr_r6_ppc64le,     gpr_r7_ppc64le,
    gpr_r8_ppc64le,   gpr_r9_ppc64le,  gpr_r10_ppc64le,    gpr_r11_ppc64le,
    gpr_r12_ppc64le,  gpr_r13_ppc64le, gpr_r14_ppc64le,    gpr_r15_ppc64le,
    gpr_r16_ppc64le,  gpr_r17_ppc64le, gpr_r18_ppc64le,    gpr_r19_ppc64le,
    gpr_r20_ppc64le,  gpr_r21_ppc64le, gpr_r22_ppc64le,    gpr_r23_ppc64le,
    gpr_r24_ppc64le,  gpr_r25_ppc64le, gpr_r26_ppc64le,    gpr_r27_ppc64le,
    gpr_r28_ppc64le,  gpr_r29_ppc64le, gpr_r30_ppc64le,    gpr_r31_ppc64le,
    gpr_pc_ppc64le,   gpr_msr_ppc64le, gpr_origr3_ppc64le, gpr_ctr_ppc64le,
    gpr_lr_ppc64le,   gpr_xer_ppc64le, gpr_cr_ppc64le,     gpr_softe_ppc64le,
    gpr_trap_ppc64le,
};

static const uint32_t g_fpr_regnums_ppc64le[] = {
    fpr_f0_ppc64le,   fpr_f1_ppc64le,  fpr_f2_ppc64le,  fpr_f3_ppc64le,
    fpr_f4_ppc64le,   fpr_f5_ppc64le,  fpr_f6_ppc64le,  fpr_f7_ppc64le,
    fpr_f8_ppc64le,   fpr_f9_ppc64le,  fpr_f10_ppc64le, fpr_f11_ppc64le,
    fpr_f12_ppc64le,  fpr_f13_ppc64le, fpr_f14_ppc64le, fpr_f15_ppc64le,
    fpr_f16_ppc64le,  fpr_f17_ppc64le, fpr_f18_ppc64le, fpr_f19_ppc64le,
    fpr_f20_ppc64le,  fpr_f21_ppc64le, fpr_f22_ppc64le, fpr_f23_ppc64le,
    fpr_f24_ppc64le,  fpr_f25_ppc64le, fpr_f26_ppc64le, fpr_f27_ppc64le,
    fpr_f28_ppc64le,  fpr_f29_ppc64le, fpr_f30_ppc64le, fpr_f31_ppc64le,
    fpr_fpscr_ppc64le,
};

static const uint32_t g_vmx_regnums_ppc64le[] = {
    vmx_vr0_ppc64le,   vmx_vr1_ppc64le,   vmx_vr2_ppc64le,  vmx_vr3_ppc64le,
    vmx_vr4_ppc64le,   vmx_vr5_ppc64le,   vmx_vr6_ppc64le,  vmx_vr7_ppc64le,
    vmx_vr8_ppc64le,   vmx_vr9_ppc64le,   vmx_vr10_ppc64le, vmx_vr11_ppc64le,
    vmx_vr12_ppc64le,  vmx_vr13_ppc64le,  vmx_vr14_ppc64le, vmx_vr15_ppc64le,
    vmx_vr16_ppc64le,  vmx_vr17_ppc64le,  vmx_vr18_ppc64le, vmx_vr19_ppc64le,
    vmx_vr20_ppc64le,  vmx_vr21_ppc64le,  vmx_vr22_ppc64le, vmx_vr23_ppc64le,
    vmx_vr24_ppc64le,  vmx_vr25_ppc64le,  vmx_vr26_ppc64le, vmx_vr27_ppc64le,
    vmx_vr28_ppc64le,  vmx_vr29_ppc64le,  vmx_vr30_ppc64le, vmx_vr31_ppc64le,
    vmx_vscr_ppc64le,  vmx_vrsave_ppc64le,
};

static const uint32_t g_vsx_regnums_ppc64le[] = {
    vsx_vs0_ppc64le,   vsx_vs1_ppc64le,   vsx_vs2_ppc64le,  vsx_vs3_ppc64le,
    vsx_vs4_ppc64le,   vsx_vs5_ppc64le,   vsx_vs6_ppc64le,  vsx_vs7_ppc64le,
    vsx_vs8_ppc64le,   vsx_vs9_ppc64le,   vsx_vs10_ppc64le, vsx_vs11_ppc64le,
    vsx_vs12_ppc64le,  vsx_vs13_ppc64le,  vsx_vs14_ppc64le, vsx_vs15_ppc64le,
    vsx_vs16_ppc64le,  vsx_vs17_ppc64le,  vsx_vs18_ppc64le, vsx_vs19_ppc64le,
    vsx_vs20_ppc64le,  vsx_vs21_ppc64le,  vsx_vs22_ppc64le, vsx_vs23_ppc64le,
    vsx_vs24_ppc64le,  vsx_vs25_ppc64le,  vsx_vs26_ppc64le, vsx_vs27_ppc64le,
    vsx_vs28_ppc64le,  vsx_vs29_ppc64le,  vsx_vs30_ppc64le, vsx_vs31_ppc64le,
    vsx_vs32_ppc64le,  vsx_vs33_ppc64le,  vsx_vs34_ppc64le, vsx_vs35_ppc64le,
    vsx_vs36_ppc64le,  vsx_vs37_ppc64le,  vsx_vs38_ppc64le, vsx_vs39_ppc64le,
    vsx_vs40_ppc64le,  vsx_vs41_ppc64le,  vsx_vs42_ppc64le, vsx_vs43_ppc64le,
    vsx_vs44_ppc64le,  vsx_vs45_ppc64le,  vsx_vs46_ppc64le, vsx_vs47_ppc64le,
    vsx_vs48_ppc64le,  vsx_vs49_ppc64le,  vsx_vs50_ppc64le, vsx_vs51_ppc64le,
    vsx_vs52_ppc64le,  vsx_vs53_ppc64le,  vsx_vs54_ppc64le, vsx_vs55_ppc64le,
    vsx_vs56_ppc64le,  vsx_vs57_ppc64le,  vsx_vs58_ppc64le, vsx_vs59_ppc64le,
    vsx_vs60_ppc64le,  vsx_vs61_ppc64le,  vsx_vs62_ppc64le, vsx_vs63_ppc64le,
};

namespace {
// Number of register sets provided by this context.
enum { k_num_register_sets = 4 };
}

static const RegisterSet g_reg_sets_ppc64le[k_num_register_sets] = {
    {"General Purpose Registers", "gpr", k_num_gpr_registers_ppc64le,
     g_gpr_regnums_ppc64le},
    {"Floating Point Registers", "fpr", k_num_fpr_registers_ppc64le,
     g_fpr_regnums_ppc64le},
    {"AltiVec/VMX Registers", "vmx", k_num_vmx_registers_ppc64le,
     g_vmx_regnums_ppc64le},
    {"VSX Registers", "vsx", k_num_vsx_registers_ppc64le,
     g_vsx_regnums_ppc64le},
};

NativeRegisterContextLinux *
NativeRegisterContextLinux::CreateHostNativeRegisterContextLinux(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread,
    uint32_t concrete_frame_idx) {
  switch (target_arch.GetMachine()) {
  case llvm::Triple::ppc64le:
    return new NativeRegisterContextLinux_ppc64le(target_arch, native_thread,
                                              concrete_frame_idx);
  default:
    llvm_unreachable("have no register context for architecture");
  }
}

NativeRegisterContextLinux_ppc64le::NativeRegisterContextLinux_ppc64le(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread,
    uint32_t concrete_frame_idx)
    : NativeRegisterContextLinux(native_thread, concrete_frame_idx,
                                 new RegisterInfoPOSIX_ppc64le(target_arch)) {
  if (target_arch.GetMachine() != llvm::Triple::ppc64le) {
    llvm_unreachable("Unhandled target architecture.");
  }

  ::memset(&m_gpr_ppc64le, 0, sizeof(m_gpr_ppc64le));
  ::memset(&m_fpr_ppc64le, 0, sizeof(m_fpr_ppc64le));
  ::memset(&m_vmx_ppc64le, 0, sizeof(m_vmx_ppc64le));
  ::memset(&m_vsx_ppc64le, 0, sizeof(m_vsx_ppc64le));
}

uint32_t NativeRegisterContextLinux_ppc64le::GetRegisterSetCount() const {
  return k_num_register_sets;
}

const RegisterSet *
NativeRegisterContextLinux_ppc64le::GetRegisterSet(uint32_t set_index) const {
  if (set_index < k_num_register_sets)
    return &g_reg_sets_ppc64le[set_index];

  return nullptr;
}

uint32_t NativeRegisterContextLinux_ppc64le::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < k_num_register_sets; ++set_index)
    count += g_reg_sets_ppc64le[set_index].num_registers;
  return count;
}

Status NativeRegisterContextLinux_ppc64le::ReadRegister(
    const RegisterInfo *reg_info, RegisterValue &reg_value) {
  Status error;

  if (!reg_info) {
    error.SetErrorString("reg_info NULL");
    return error;
  }

  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];

  if (IsFPR(reg)) {
    error = ReadFPR();
    if (error.Fail())
      return error;

    // Get pointer to m_fpr_ppc64le variable and set the data from it.
    uint32_t fpr_offset = CalculateFprOffset(reg_info);
    assert(fpr_offset < sizeof m_fpr_ppc64le);
    uint8_t *src = (uint8_t *)&m_fpr_ppc64le + fpr_offset;
    reg_value.SetFromMemoryData(reg_info, src, reg_info->byte_size,
                                eByteOrderLittle, error);
  } else if (IsVSX(reg)) {
    uint32_t vsx_offset = CalculateVsxOffset(reg_info);
    assert(vsx_offset < 16*64);

    if (vsx_offset < 16*32) {
      error = ReadVSX();
      if (error.Fail())
        return error;

      error = ReadFPR();
      if (error.Fail())
        return error;

      uint64_t value[2];
      uint8_t *dst, *src;
      dst = (uint8_t *) &value;
      src = (uint8_t *) &m_vsx_ppc64le + vsx_offset / 2;
      ::memcpy(dst, src, 8);
      dst += 8;
      src = (uint8_t *) &m_fpr_ppc64le + vsx_offset / 2;
      ::memcpy(dst, src, 8);
      reg_value.SetFromMemoryData(reg_info, &value, reg_info->byte_size,
                                  eByteOrderLittle, error);
    } else {
      error = ReadVMX();
      if (error.Fail())
        return error;

      // Get pointer to m_vmx_ppc64le variable and set the data from it.
      uint32_t vmx_offset = vsx_offset -16*32;
      uint8_t *src = (uint8_t *) &m_vmx_ppc64le + vmx_offset;
      reg_value.SetFromMemoryData(reg_info, src, reg_info->byte_size,
                                       eByteOrderLittle, error);
    }
  } else if (IsVMX(reg)) {
    error = ReadVMX();
    if (error.Fail())
      return error;

    // Get pointer to m_vmx_ppc64le variable and set the data from it.
    uint32_t vmx_offset = CalculateVmxOffset(reg_info);
    assert(vmx_offset < sizeof m_vmx_ppc64le);
    uint8_t *src = (uint8_t *) &m_vmx_ppc64le + vmx_offset;
    reg_value.SetFromMemoryData(reg_info, src, reg_info->byte_size,
                                eByteOrderLittle, error);
  } else if (IsGPR(reg)) {
    error = ReadGPR();
    if (error.Fail())
      return error;

    uint8_t *src = (uint8_t *) &m_gpr_ppc64le + reg_info->byte_offset;
    reg_value.SetFromMemoryData(reg_info, src, reg_info->byte_size,
                                eByteOrderLittle, error);
  } else {
    return Status("failed - register wasn't recognized to be a GPR, FPR, VSX "\
                  "or VMX, read strategy unknown");
  }

  return error;
}

Status NativeRegisterContextLinux_ppc64le::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &reg_value) {
  Status error;
  if (!reg_info)
    return Status("reg_info NULL");

  const uint32_t reg_index = reg_info->kinds[lldb::eRegisterKindLLDB];
  if (reg_index == LLDB_INVALID_REGNUM)
    return Status("no lldb regnum for %s", reg_info && reg_info->name
                                               ? reg_info->name
                                               : "<unknown register>");

  if (IsGPR(reg_index)) {
    error = ReadGPR();
    if (error.Fail())
      return error;

    uint8_t *dst = (uint8_t *) &m_gpr_ppc64le + reg_info->byte_offset;
    ::memcpy(dst, reg_value.GetBytes(), reg_value.GetByteSize());

    error = WriteGPR();
    if (error.Fail())
      return error;

    return Status();
  }

  if (IsFPR(reg_index)) {
    error = ReadFPR();
    if (error.Fail())
      return error;

    // Get pointer to m_fpr_ppc64le variable and set the data to it.
    uint32_t fpr_offset = CalculateFprOffset(reg_info);
    assert(fpr_offset < GetFPRSize());
    uint8_t *dst = (uint8_t *) &m_fpr_ppc64le + fpr_offset;
    ::memcpy(dst, reg_value.GetBytes(), reg_value.GetByteSize());

    error = WriteFPR();
    if (error.Fail())
      return error;

    return Status();
  }

  if (IsVMX(reg_index)) {
    error = ReadVMX();
    if (error.Fail())
      return error;

    // Get pointer to m_vmx_ppc64le variable and set the data to it.
    uint32_t vmx_offset = CalculateVmxOffset(reg_info);
    assert(vmx_offset < GetVMXSize());
    uint8_t *dst = (uint8_t *)&m_vmx_ppc64le + vmx_offset;
    ::memcpy(dst, reg_value.GetBytes(), reg_value.GetByteSize());

    error = WriteVMX();
    if (error.Fail())
      return error;

    return Status();
  }

  if (IsVSX(reg_index)) {
    uint32_t vsx_offset = CalculateVsxOffset(reg_info);
    assert(vsx_offset < 16*64);

    if (vsx_offset < 16*32) {
      error = ReadVSX();
      if (error.Fail())
        return error;

      error = ReadFPR();
      if (error.Fail())
        return error;

      uint64_t value[2];
      ::memcpy(value, reg_value.GetBytes(), 16);
      uint8_t *dst, *src;
      src = (uint8_t *) value;
      dst = (uint8_t *) &m_vsx_ppc64le + vsx_offset / 2;
      ::memcpy(dst, src, 8);
      src += 8;
      dst = (uint8_t *) &m_fpr_ppc64le + vsx_offset / 2;
      ::memcpy(dst, src, 8);

      WriteVSX();
      WriteFPR();
    } else {
      error = ReadVMX();
      if (error.Fail())
        return error;

      // Get pointer to m_vmx_ppc64le variable and set the data from it.
      uint32_t vmx_offset = vsx_offset -16*32;
      uint8_t *dst = (uint8_t *) &m_vmx_ppc64le + vmx_offset;
      ::memcpy(dst, reg_value.GetBytes(), reg_value.GetByteSize());
      WriteVMX();
    }

    return Status();
  }

  return Status("failed - register wasn't recognized to be a GPR, FPR, VSX "\
                "or VMX, write strategy unknown");
}

Status NativeRegisterContextLinux_ppc64le::ReadAllRegisterValues(
    lldb::DataBufferSP &data_sp) {
  Status error;

  data_sp.reset(new DataBufferHeap(REG_CONTEXT_SIZE, 0));
  if (!data_sp)
    return Status("failed to allocate DataBufferHeap instance of size %" PRIu64,
                  REG_CONTEXT_SIZE);

  error = ReadGPR();
  if (error.Fail())
    return error;

  error = ReadFPR();
  if (error.Fail())
    return error;

  error = ReadVMX();
  if (error.Fail())
    return error;

  error = ReadVSX();
  if (error.Fail())
    return error;

  uint8_t *dst = data_sp->GetBytes();
  if (dst == nullptr) {
    error.SetErrorStringWithFormat("DataBufferHeap instance of size %" PRIu64
                                   " returned a null pointer",
                                   REG_CONTEXT_SIZE);
    return error;
  }

  ::memcpy(dst, &m_gpr_ppc64le, GetGPRSize());
  dst += GetGPRSize();
  ::memcpy(dst, &m_fpr_ppc64le, GetFPRSize());
  dst += GetFPRSize();
  ::memcpy(dst, &m_vmx_ppc64le, GetVMXSize());
  dst += GetVMXSize();
  ::memcpy(dst, &m_vsx_ppc64le, GetVSXSize());

  return error;
}

Status NativeRegisterContextLinux_ppc64le::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  Status error;

  if (!data_sp) {
    error.SetErrorStringWithFormat(
        "NativeRegisterContextLinux_ppc64le::%s invalid data_sp provided",
        __FUNCTION__);
    return error;
  }

  if (data_sp->GetByteSize() != REG_CONTEXT_SIZE) {
    error.SetErrorStringWithFormat(
        "NativeRegisterContextLinux_ppc64le::%s data_sp contained mismatched "
        "data size, expected %" PRIu64 ", actual %" PRIu64,
        __FUNCTION__, REG_CONTEXT_SIZE, data_sp->GetByteSize());
    return error;
  }

  uint8_t *src = data_sp->GetBytes();
  if (src == nullptr) {
    error.SetErrorStringWithFormat("NativeRegisterContextLinux_ppc64le::%s "
                                   "DataBuffer::GetBytes() returned a null "
                                   "pointer",
                                   __FUNCTION__);
    return error;
  }

  ::memcpy(&m_gpr_ppc64le, src, GetGPRSize());
  error = WriteGPR();
  if (error.Fail())
    return error;

  src += GetGPRSize();
  ::memcpy(&m_fpr_ppc64le, src, GetFPRSize());

  error = WriteFPR();
  if (error.Fail())
    return error;

  src += GetFPRSize();
  ::memcpy(&m_vmx_ppc64le, src, GetVMXSize());

  error = WriteVMX();
  if (error.Fail())
    return error;

  src += GetVMXSize();
  ::memcpy(&m_vsx_ppc64le, src, GetVSXSize());
  error = WriteVSX();

  return error;
}

bool NativeRegisterContextLinux_ppc64le::IsGPR(unsigned reg) const {
  return reg <= k_last_gpr_ppc64le; // GPR's come first.
}

bool NativeRegisterContextLinux_ppc64le::IsFPR(unsigned reg) const {
  return (k_first_fpr_ppc64le <= reg && reg <= k_last_fpr_ppc64le);
}

Status NativeRegisterContextLinux_ppc64le::DoReadGPR(
    void *buf, size_t buf_size) {
  int regset = NT_PRSTATUS;
  return NativeProcessLinux::PtraceWrapper(PTRACE_GETREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::DoWriteGPR(
    void *buf, size_t buf_size) {
  int regset = NT_PRSTATUS;
  return NativeProcessLinux::PtraceWrapper(PTRACE_SETREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::DoReadFPR(
    void *buf, size_t buf_size) {
  int regset = NT_FPREGSET;
  return NativeProcessLinux::PtraceWrapper(PTRACE_GETFPREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);

}

Status NativeRegisterContextLinux_ppc64le::DoWriteFPR(
    void *buf, size_t buf_size) {
  int regset = NT_FPREGSET;
  return NativeProcessLinux::PtraceWrapper(PTRACE_SETFPREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);
}

uint32_t NativeRegisterContextLinux_ppc64le::CalculateFprOffset(
    const RegisterInfo *reg_info) const {
  return reg_info->byte_offset -
         GetRegisterInfoAtIndex(k_first_fpr_ppc64le)->byte_offset;
}

uint32_t NativeRegisterContextLinux_ppc64le::CalculateVmxOffset(
    const RegisterInfo *reg_info) const {
  return reg_info->byte_offset -
         GetRegisterInfoAtIndex(k_first_vmx_ppc64le)->byte_offset;
}

uint32_t NativeRegisterContextLinux_ppc64le::CalculateVsxOffset(
    const RegisterInfo *reg_info) const {
  return reg_info->byte_offset -
         GetRegisterInfoAtIndex(k_first_vsx_ppc64le)->byte_offset;
}

Status NativeRegisterContextLinux_ppc64le::DoReadVMX(
    void *buf, size_t buf_size) {
  int regset = NT_PPC_VMX;
  return NativeProcessLinux::PtraceWrapper(PTRACE_GETVRREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::DoWriteVMX(
    void *buf, size_t buf_size) {
  int regset = NT_PPC_VMX;
  return NativeProcessLinux::PtraceWrapper(PTRACE_SETVRREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::DoReadVSX(
    void *buf, size_t buf_size) {
  int regset = NT_PPC_VSX;
  return NativeProcessLinux::PtraceWrapper(PTRACE_GETVSRREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::DoWriteVSX(
    void *buf, size_t buf_size) {
  int regset = NT_PPC_VSX;
  return NativeProcessLinux::PtraceWrapper(PTRACE_SETVSRREGS, m_thread.GetID(),
                                           &regset, buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::ReadVMX() {
  void *buf = GetVMXBuffer();
  if (!buf)
    return Status("VMX buffer is NULL");
  size_t buf_size = GetVMXSize();

  return DoReadVMX(buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::WriteVMX() {
  void *buf = GetVMXBuffer();
  if (!buf)
    return Status("VMX buffer is NULL");
  size_t buf_size = GetVMXSize();

  return DoWriteVMX(buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::ReadVSX() {
  void *buf = GetVSXBuffer();
  if (!buf)
    return Status("VSX buffer is NULL");
  size_t buf_size = GetVSXSize();

  return DoReadVSX(buf, buf_size);
}

Status NativeRegisterContextLinux_ppc64le::WriteVSX() {
  Status error;
  uint8_t *dst = (uint8_t *) GetVSXBuffer();
  if (!dst)
    return Status("VSX buffer is NULL");

  size_t buf_size = GetVSXSize();
  error = DoWriteVSX(dst, buf_size);

  return error;
}

bool NativeRegisterContextLinux_ppc64le::IsVMX(unsigned reg) {
  return (reg >= k_first_vmx_ppc64le) && (reg <= k_last_vmx_ppc64le);
}

bool NativeRegisterContextLinux_ppc64le::IsVSX(unsigned reg) {
  return (reg >= k_first_vsx_ppc64le) && (reg <= k_last_vsx_ppc64le);
}

#endif // defined(__powerpc64__)
