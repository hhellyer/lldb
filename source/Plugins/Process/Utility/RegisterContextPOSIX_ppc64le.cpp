//===-- RegisterContextPOSIX_ppc64le.cpp -------------------------*- C++
//-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <cstring>
#include <errno.h>
#include <stdint.h>

#include "lldb/Core/RegisterValue.h"
#include "lldb/Core/Scalar.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Endian.h"
#include "llvm/Support/Compiler.h"

#include "Plugins/Process/elf-core/ProcessElfCore.h"
#include "RegisterContextPOSIX_ppc64le.h"

using namespace lldb_private;
using namespace lldb;

static const uint32_t g_gpr_regnums[] = {
    gpr_r0_ppc64le,  gpr_r1_ppc64le,  gpr_r2_ppc64le,  gpr_r3_ppc64le,
    gpr_r4_ppc64le,  gpr_r5_ppc64le,  gpr_r6_ppc64le,  gpr_r7_ppc64le,
    gpr_r8_ppc64le,  gpr_r9_ppc64le,  gpr_r10_ppc64le, gpr_r11_ppc64le,
    gpr_r12_ppc64le, gpr_r13_ppc64le, gpr_r14_ppc64le, gpr_r15_ppc64le,
    gpr_r16_ppc64le, gpr_r17_ppc64le, gpr_r18_ppc64le, gpr_r19_ppc64le,
    gpr_r20_ppc64le, gpr_r21_ppc64le, gpr_r22_ppc64le, gpr_r23_ppc64le,
    gpr_r24_ppc64le, gpr_r25_ppc64le, gpr_r26_ppc64le, gpr_r27_ppc64le,
    gpr_r28_ppc64le, gpr_r29_ppc64le, gpr_r30_ppc64le, gpr_r31_ppc64le,
    gpr_pc_ppc64le, gpr_msr_ppc64le, gpr_origr3_ppc64le, gpr_ctr_ppc64le,
    gpr_lr_ppc64le, gpr_xer_ppc64le, gpr_cr_ppc64le, gpr_softe_ppc64le,
    gpr_trap_ppc64le,
};

static const uint32_t g_fpr_regnums[] = {
    fpr_f0_ppc64le,    fpr_f1_ppc64le,  fpr_f2_ppc64le,  fpr_f3_ppc64le,
    fpr_f4_ppc64le,    fpr_f5_ppc64le,  fpr_f6_ppc64le,  fpr_f7_ppc64le,
    fpr_f8_ppc64le,    fpr_f9_ppc64le,  fpr_f10_ppc64le, fpr_f11_ppc64le,
    fpr_f12_ppc64le,   fpr_f13_ppc64le, fpr_f14_ppc64le, fpr_f15_ppc64le,
    fpr_f16_ppc64le,   fpr_f17_ppc64le, fpr_f18_ppc64le, fpr_f19_ppc64le,
    fpr_f20_ppc64le,   fpr_f21_ppc64le, fpr_f22_ppc64le, fpr_f23_ppc64le,
    fpr_f24_ppc64le,   fpr_f25_ppc64le, fpr_f26_ppc64le, fpr_f27_ppc64le,
    fpr_f28_ppc64le,   fpr_f29_ppc64le, fpr_f30_ppc64le, fpr_f31_ppc64le,
    fpr_fpscr_ppc64le,
};

static const uint32_t g_vmx_regnums[] = {
    vmx_v0_ppc64le,     vmx_v1_ppc64le,   vmx_v2_ppc64le,  vmx_v3_ppc64le,
    vmx_v4_ppc64le,     vmx_v5_ppc64le,   vmx_v6_ppc64le,  vmx_v7_ppc64le,
    vmx_v8_ppc64le,     vmx_v9_ppc64le,   vmx_v10_ppc64le, vmx_v11_ppc64le,
    vmx_v12_ppc64le,    vmx_v13_ppc64le,  vmx_v14_ppc64le, vmx_v15_ppc64le,
    vmx_v16_ppc64le,    vmx_v17_ppc64le,  vmx_v18_ppc64le, vmx_v19_ppc64le,
    vmx_v20_ppc64le,    vmx_v21_ppc64le,  vmx_v22_ppc64le, vmx_v23_ppc64le,
    vmx_v24_ppc64le,    vmx_v25_ppc64le,  vmx_v26_ppc64le, vmx_v27_ppc64le,
    vmx_v28_ppc64le,    vmx_v29_ppc64le,  vmx_v30_ppc64le, vmx_v31_ppc64le,
    vmx_vscr_ppc64le,
};

// Number of register sets provided by this context.
enum { k_num_register_sets = 3 };

static const RegisterSet g_reg_sets_ppc64le[k_num_register_sets] = {
    {"General Purpose Registers", "gpr", k_num_gpr_registers_ppc64le,
     g_gpr_regnums},
    {"Floating Point Registers", "fpr", k_num_fpr_registers_ppc64le,
     g_fpr_regnums},
    {"Altivec/VMX Registers", "vmx", k_num_vmx_registers_ppc64le,
     g_vmx_regnums},
};

static_assert(k_first_gpr_ppc64le == 0,
              "GPRs must index starting at 0, or fix IsGPR()");
bool RegisterContextPOSIX_ppc64le::IsGPR(unsigned reg) {
  return reg <= m_reg_info.last_gpr; // GPR's come first.
}

bool RegisterContextPOSIX_ppc64le::IsFPR(unsigned reg) {
  return (m_reg_info.first_fpr <= reg && reg <= m_reg_info.last_fpr);
}

bool RegisterContextPOSIX_ppc64le::IsVMX(unsigned reg) {
  return (m_reg_info.first_fpr_v <= reg) && (reg <= m_reg_info.last_fpr_v);
}

RegisterContextPOSIX_ppc64le::RegisterContextPOSIX_ppc64le(
    Thread &thread, uint32_t concrete_frame_idx,
    RegisterInfoInterface *register_info)
    : RegisterContext(thread, concrete_frame_idx) {
  m_register_info_ap.reset(register_info);

  // elf-core yet to support ReadFPR()
  ProcessSP base = CalculateProcess();
  if (base.get()->GetPluginName() == ProcessElfCore::GetPluginNameStatic())
    return;
}

RegisterContextPOSIX_ppc64le::~RegisterContextPOSIX_ppc64le() {}

void RegisterContextPOSIX_ppc64le::Invalidate() {}

void RegisterContextPOSIX_ppc64le::InvalidateAllRegisters() {}

unsigned RegisterContextPOSIX_ppc64le::GetRegisterOffset(unsigned reg) {
  assert(reg < k_num_registers_ppc64le && "Invalid register number.");
  return GetRegisterInfo()[reg].byte_offset;
}

unsigned RegisterContextPOSIX_ppc64le::GetRegisterSize(unsigned reg) {
  assert(reg < k_num_registers_ppc64le && "Invalid register number.");
  return GetRegisterInfo()[reg].byte_size;
}

size_t RegisterContextPOSIX_ppc64le::GetRegisterCount() {
  size_t num_registers = k_num_registers_ppc64le;
  return num_registers;
}

size_t RegisterContextPOSIX_ppc64le::GetGPRSize() {
  return m_register_info_ap->GetGPRSize();
}

const RegisterInfo *RegisterContextPOSIX_ppc64le::GetRegisterInfo() {
  // Commonly, this method is overridden and g_register_infos is copied and
  // specialized.
  // So, use GetRegisterInfo() rather than g_register_infos in this scope.
  return m_register_info_ap->GetRegisterInfo();
}

const RegisterInfo *
RegisterContextPOSIX_ppc64le::GetRegisterInfoAtIndex(size_t reg) {
  if (reg < k_num_registers_ppc64le)
    return &GetRegisterInfo()[reg];
  else
    return NULL;
}

size_t RegisterContextPOSIX_ppc64le::GetRegisterSetCount() {
  size_t sets = 0;
  for (size_t set = 0; set < k_num_register_sets; ++set) {
    if (IsRegisterSetAvailable(set))
      ++sets;
  }

  return sets;
}

const RegisterSet *RegisterContextPOSIX_ppc64le::GetRegisterSet(size_t set) {
  if (IsRegisterSetAvailable(set))
    return &g_reg_sets_ppc64le[set];
  else
    return NULL;
}

const char *RegisterContextPOSIX_ppc64le::GetRegisterName(unsigned reg) {
  assert(reg < k_num_registers_ppc64le && "Invalid register offset.");
  return GetRegisterInfo()[reg].name;
}

lldb::ByteOrder RegisterContextPOSIX_ppc64le::GetByteOrder() {
  // Get the target process whose privileged thread was used for the register
  // read.
  lldb::ByteOrder byte_order = eByteOrderInvalid;
  Process *process = CalculateProcess().get();

  if (process)
    byte_order = process->GetByteOrder();
  return byte_order;
}

bool RegisterContextPOSIX_ppc64le::IsRegisterSetAvailable(size_t set_index) {
  size_t num_sets = k_num_register_sets;

  return (set_index < num_sets);
}

// Used when parsing DWARF and EH frame information and any other
// object file sections that contain register numbers in them.
uint32_t RegisterContextPOSIX_ppc64le::ConvertRegisterKindToRegisterNumber(
    lldb::RegisterKind kind, uint32_t num) {
  const uint32_t num_regs = GetRegisterCount();

  assert(kind < kNumRegisterKinds);
  for (uint32_t reg_idx = 0; reg_idx < num_regs; ++reg_idx) {
    const RegisterInfo *reg_info = GetRegisterInfoAtIndex(reg_idx);

    if (reg_info->kinds[kind] == num)
      return reg_idx;
  }

  return LLDB_INVALID_REGNUM;
}
