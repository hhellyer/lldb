//===-- lldb-ppc64le-register-enums.h -----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef lldb_ppc64le_register_enums_h
#define lldb_ppc64le_register_enums_h

// LLDB register codes (e.g. RegisterKind == eRegisterKindLLDB)

// ---------------------------------------------------------------------------
// Internal codes for all ppc64le registers.
// ---------------------------------------------------------------------------
enum {
  k_first_gpr_ppc64le,
  gpr_r0_ppc64le = k_first_gpr_ppc64le,
  gpr_r1_ppc64le,
  gpr_r2_ppc64le,
  gpr_r3_ppc64le,
  gpr_r4_ppc64le,
  gpr_r5_ppc64le,
  gpr_r6_ppc64le,
  gpr_r7_ppc64le,
  gpr_r8_ppc64le,
  gpr_r9_ppc64le,
  gpr_r10_ppc64le,
  gpr_r11_ppc64le,
  gpr_r12_ppc64le,
  gpr_r13_ppc64le,
  gpr_r14_ppc64le,
  gpr_r15_ppc64le,
  gpr_r16_ppc64le,
  gpr_r17_ppc64le,
  gpr_r18_ppc64le,
  gpr_r19_ppc64le,
  gpr_r20_ppc64le,
  gpr_r21_ppc64le,
  gpr_r22_ppc64le,
  gpr_r23_ppc64le,
  gpr_r24_ppc64le,
  gpr_r25_ppc64le,
  gpr_r26_ppc64le,
  gpr_r27_ppc64le,
  gpr_r28_ppc64le,
  gpr_r29_ppc64le,
  gpr_r30_ppc64le,
  gpr_r31_ppc64le,
  gpr_pc_ppc64le,
  gpr_msr_ppc64le,
  gpr_origr3_ppc64le,
  gpr_ctr_ppc64le,
  gpr_lr_ppc64le,
  gpr_xer_ppc64le,
  gpr_cr_ppc64le,
  gpr_trap_ppc64le,
  k_last_gpr_ppc64le = gpr_trap_ppc64le,

  k_first_fpr_ppc64le,
  fpr_f0_ppc64le = k_first_fpr_ppc64le,
  fpr_f1_ppc64le,
  fpr_f2_ppc64le,
  fpr_f3_ppc64le,
  fpr_f4_ppc64le,
  fpr_f5_ppc64le,
  fpr_f6_ppc64le,
  fpr_f7_ppc64le,
  fpr_f8_ppc64le,
  fpr_f9_ppc64le,
  fpr_f10_ppc64le,
  fpr_f11_ppc64le,
  fpr_f12_ppc64le,
  fpr_f13_ppc64le,
  fpr_f14_ppc64le,
  fpr_f15_ppc64le,
  fpr_f16_ppc64le,
  fpr_f17_ppc64le,
  fpr_f18_ppc64le,
  fpr_f19_ppc64le,
  fpr_f20_ppc64le,
  fpr_f21_ppc64le,
  fpr_f22_ppc64le,
  fpr_f23_ppc64le,
  fpr_f24_ppc64le,
  fpr_f25_ppc64le,
  fpr_f26_ppc64le,
  fpr_f27_ppc64le,
  fpr_f28_ppc64le,
  fpr_f29_ppc64le,
  fpr_f30_ppc64le,
  fpr_f31_ppc64le,
  fpr_fpscr_ppc64le,
  k_last_fpr_ppc64le = fpr_fpscr_ppc64le,

  k_first_vmx_ppc64le,
  vmx_v0_ppc64le = k_first_vmx_ppc64le,
  vmx_v1_ppc64le,
  vmx_v2_ppc64le,
  vmx_v3_ppc64le,
  vmx_v4_ppc64le,
  vmx_v5_ppc64le,
  vmx_v6_ppc64le,
  vmx_v7_ppc64le,
  vmx_v8_ppc64le,
  vmx_v9_ppc64le,
  vmx_v10_ppc64le,
  vmx_v11_ppc64le,
  vmx_v12_ppc64le,
  vmx_v13_ppc64le,
  vmx_v14_ppc64le,
  vmx_v15_ppc64le,
  vmx_v16_ppc64le,
  vmx_v17_ppc64le,
  vmx_v18_ppc64le,
  vmx_v19_ppc64le,
  vmx_v20_ppc64le,
  vmx_v21_ppc64le,
  vmx_v22_ppc64le,
  vmx_v23_ppc64le,
  vmx_v24_ppc64le,
  vmx_v25_ppc64le,
  vmx_v26_ppc64le,
  vmx_v27_ppc64le,
  vmx_v28_ppc64le,
  vmx_v29_ppc64le,
  vmx_v30_ppc64le,
  vmx_v31_ppc64le,
//  vmx_vrsave_ppc64le,
//  vmx_vscr_ppc64le,
//  k_last_vmx_ppc64le = vmx_vscr_ppc64le,
  k_last_vmx_ppc64le = vmx_v31_ppc64le,

  k_num_registers_ppc64le,
  k_num_gpr_registers_ppc64le = k_last_gpr_ppc64le - k_first_gpr_ppc64le + 1,
  k_num_fpr_registers_ppc64le = k_last_fpr_ppc64le - k_first_fpr_ppc64le + 1,
  k_num_vmx_registers_ppc64le = k_last_vmx_ppc64le - k_first_vmx_ppc64le + 1,
};

#endif // #ifndef lldb_ppc64le_register_enums_h
