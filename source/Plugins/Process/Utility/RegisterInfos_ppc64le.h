//===-- RegisterInfos_ppc64le.h -----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifdef DECLARE_REGISTER_INFOS_PPC64LE_STRUCT

// C Includes
#include <stddef.h>

// Computes the offset of the given GPR in the user data area.
#define GPR_OFFSET(regname) (offsetof(GPR, regname))
#define FPR_OFFSET(regname) (offsetof(FPR, regname))
#define VMX_OFFSET(regname) (offsetof(VMX, regname))
#define GPR_SIZE(regname) (sizeof(((GPR *)NULL)->regname))

#include "Utility/PPC64LE_DWARF_Registers.h"
#include "lldb-ppc64le-register-enums.h"

// Note that the size and offset will be updated by platform-specific classes.
#define DEFINE_GPR(reg, alt, lldb_kind)                                        \
  {                                                                            \
    #reg, alt, GPR_SIZE(reg), GPR_OFFSET(reg), lldb::eEncodingUint,            \
                                         lldb::eFormatHex,                     \
                                         {ppc64le_dwarf::dwarf_##reg##_ppc64le,\
                                          ppc64le_dwarf::dwarf_##reg##_ppc64le,\
                                          lldb_kind,                           \
                                          LLDB_INVALID_REGNUM,                 \
                                          gpr_##reg##_ppc64le },               \
                                          NULL, NULL, NULL, 0                  \
  }
#define DEFINE_FPR(reg, alt, lldb_kind)                                        \
  {                                                                            \
    #reg, alt, 8, FPR_OFFSET(reg), lldb::eEncodingIEEE754, lldb::eFormatFloat, \
                              {ppc64le_dwarf::dwarf_##reg##_ppc64le,           \
                               ppc64le_dwarf::dwarf_##reg##_ppc64le,           \
                               lldb_kind, LLDB_INVALID_REGNUM,                 \
                               fpr_##reg##_ppc64le },                          \
                               NULL, NULL, NULL, 0                             \
  }
#define DEFINE_VMX(reg, lldb_kind)                                             \
  {                                                                            \
    #reg, NULL, 16, VMX_OFFSET(reg), lldb::eEncodingVector,                    \
                               lldb::eFormatVectorOfUInt32,                    \
                               {ppc64le_dwarf::dwarf_##reg##_ppc64le,          \
                                ppc64le_dwarf::dwarf_##reg##_ppc64le,          \
                                lldb_kind, LLDB_INVALID_REGNUM,                \
                                vmx_##reg##_ppc64le },                         \
                                NULL, NULL, NULL, 0                            \
  }

// General purpose registers.            EH_Frame,                  DWARF,
// Generic,                Process Plugin
#define POWERPC_REGS                                                           \
  DEFINE_GPR(r0, NULL, LLDB_INVALID_REGNUM)                                    \
  , DEFINE_GPR(r1, "sp", LLDB_REGNUM_GENERIC_SP),                              \
      DEFINE_GPR(r2, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_GPR(r3, "arg1", LLDB_REGNUM_GENERIC_ARG1),                        \
      DEFINE_GPR(r4, "arg2", LLDB_REGNUM_GENERIC_ARG2),                        \
      DEFINE_GPR(r5, "arg3", LLDB_REGNUM_GENERIC_ARG3),                        \
      DEFINE_GPR(r6, "arg4", LLDB_REGNUM_GENERIC_ARG4),                        \
      DEFINE_GPR(r7, "arg5", LLDB_REGNUM_GENERIC_ARG5),                        \
      DEFINE_GPR(r8, "arg6", LLDB_REGNUM_GENERIC_ARG6),                        \
      DEFINE_GPR(r9, "arg7", LLDB_REGNUM_GENERIC_ARG7),                        \
      DEFINE_GPR(r10, "arg8", LLDB_REGNUM_GENERIC_ARG8),                       \
      DEFINE_GPR(r11, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r12, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r13, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r14, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r15, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r16, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r17, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r18, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r19, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r20, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r21, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r22, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r23, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r24, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r25, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r26, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r27, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r28, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r29, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r30, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(r31, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_GPR(pc, "pc", LLDB_REGNUM_GENERIC_PC),                            \
      DEFINE_GPR(lr, "lr", LLDB_REGNUM_GENERIC_RA),                            \
      DEFINE_GPR(msr, "msr", LLDB_INVALID_REGNUM),                             \
      DEFINE_GPR(origr3, "orig_r3", LLDB_INVALID_REGNUM),                      \
      DEFINE_GPR(ctr, "ctr", LLDB_INVALID_REGNUM),                             \
      DEFINE_GPR(xer, "xer", LLDB_INVALID_REGNUM),                             \
      DEFINE_GPR(cr, "cr", LLDB_REGNUM_GENERIC_FLAGS),                         \
      DEFINE_GPR(softe, "softe", LLDB_INVALID_REGNUM),                         \
      DEFINE_GPR(trap, "trap", LLDB_INVALID_REGNUM),                           \
      DEFINE_FPR(f0, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f1, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f2, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f3, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f4, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f5, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f6, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f7, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f8, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f9, NULL, LLDB_INVALID_REGNUM),                               \
      DEFINE_FPR(f10, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f11, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f12, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f13, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f14, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f15, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f16, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f17, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f18, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f19, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f20, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f21, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f22, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f23, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f24, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f25, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f26, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f27, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f28, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f29, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f30, NULL, LLDB_INVALID_REGNUM),                              \
      DEFINE_FPR(f31, NULL, LLDB_INVALID_REGNUM),                              \
      {"fpscr",                                                                \
       NULL,                                                                   \
       8,                                                                      \
       FPR_OFFSET(fpscr),                                                      \
       lldb::eEncodingUint,                                                    \
       lldb::eFormatHex,                                                       \
       {ppc64le_dwarf::dwarf_fpscr_ppc64le,                                    \
        ppc64le_dwarf::dwarf_fpscr_ppc64le, LLDB_INVALID_REGNUM,               \
        LLDB_INVALID_REGNUM, fpr_fpscr_ppc64le},                               \
       NULL,                                                                   \
       NULL,                                                                   \
       NULL,                                                                   \
       0},                                                                     \
      DEFINE_VMX(vr0, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr1, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr2, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr3, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr4, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr5, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr6, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr7, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr8, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr9, LLDB_INVALID_REGNUM),                                    \
      DEFINE_VMX(vr10, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr11, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr12, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr13, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr14, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr15, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr16, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr17, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr18, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr19, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr20, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr21, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr22, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr23, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr24, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr25, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr26, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr27, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr28, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr29, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr30, LLDB_INVALID_REGNUM),                                   \
      DEFINE_VMX(vr31, LLDB_INVALID_REGNUM),                                   \
      {"vscr",                                                                 \
       NULL,                                                                   \
       4,                                                                      \
       VMX_OFFSET(vscr),                                                       \
       lldb::eEncodingUint,                                                    \
       lldb::eFormatHex,                                                       \
       {ppc64le_dwarf::dwarf_vscr_ppc64le,                                     \
        ppc64le_dwarf::dwarf_vscr_ppc64le, LLDB_INVALID_REGNUM,                \
        LLDB_INVALID_REGNUM, vmx_vscr_ppc64le},                                \
       NULL,                                                                   \
       NULL,                                                                   \
       NULL,                                                                   \
       0},                                                                     \
      {"vrsave",                                                               \
       NULL,                                                                   \
       4,                                                                      \
       VMX_OFFSET(vrsave),                                                     \
       lldb::eEncodingUint,                                                    \
       lldb::eFormatHex,                                                       \
       {ppc64le_dwarf::dwarf_vrsave_ppc64le,                                   \
        ppc64le_dwarf::dwarf_vrsave_ppc64le, LLDB_INVALID_REGNUM,              \
        LLDB_INVALID_REGNUM, vmx_vrsave_ppc64le},                              \
       NULL,                                                                   \
       NULL,                                                                   \
       NULL,                                                                   \
       0},                                                                     \
      /* */

typedef struct _GPR {
  uint64_t r0;
  uint64_t r1;
  uint64_t r2;
  uint64_t r3;
  uint64_t r4;
  uint64_t r5;
  uint64_t r6;
  uint64_t r7;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t r16;
  uint64_t r17;
  uint64_t r18;
  uint64_t r19;
  uint64_t r20;
  uint64_t r21;
  uint64_t r22;
  uint64_t r23;
  uint64_t r24;
  uint64_t r25;
  uint64_t r26;
  uint64_t r27;
  uint64_t r28;
  uint64_t r29;
  uint64_t r30;
  uint64_t r31;
  uint64_t pc;
  uint64_t msr;
  uint64_t origr3;
  uint64_t ctr;
  uint64_t lr;
  uint64_t xer;
  uint64_t cr;
  uint64_t softe;
  uint64_t trap;
} GPR;

typedef struct _FPR {
  uint64_t f0;
  uint64_t f1;
  uint64_t f2;
  uint64_t f3;
  uint64_t f4;
  uint64_t f5;
  uint64_t f6;
  uint64_t f7;
  uint64_t f8;
  uint64_t f9;
  uint64_t f10;
  uint64_t f11;
  uint64_t f12;
  uint64_t f13;
  uint64_t f14;
  uint64_t f15;
  uint64_t f16;
  uint64_t f17;
  uint64_t f18;
  uint64_t f19;
  uint64_t f20;
  uint64_t f21;
  uint64_t f22;
  uint64_t f23;
  uint64_t f24;
  uint64_t f25;
  uint64_t f26;
  uint64_t f27;
  uint64_t f28;
  uint64_t f29;
  uint64_t f30;
  uint64_t f31;
  uint64_t fpscr;
} FPR;

typedef struct _VMX {
  uint32_t vr0[4];
  uint32_t vr1[4];
  uint32_t vr2[4];
  uint32_t vr3[4];
  uint32_t vr4[4];
  uint32_t vr5[4];
  uint32_t vr6[4];
  uint32_t vr7[4];
  uint32_t vr8[4];
  uint32_t vr9[4];
  uint32_t vr10[4];
  uint32_t vr11[4];
  uint32_t vr12[4];
  uint32_t vr13[4];
  uint32_t vr14[4];
  uint32_t vr15[4];
  uint32_t vr16[4];
  uint32_t vr17[4];
  uint32_t vr18[4];
  uint32_t vr19[4];
  uint32_t vr20[4];
  uint32_t vr21[4];
  uint32_t vr22[4];
  uint32_t vr23[4];
  uint32_t vr24[4];
  uint32_t vr25[4];
  uint32_t vr26[4];
  uint32_t vr27[4];
  uint32_t vr28[4];
  uint32_t vr29[4];
  uint32_t vr30[4];
  uint32_t vr31[4];
  uint32_t vscr[4];
  uint32_t vrsave[4];
} VMX;
static lldb_private::RegisterInfo g_register_infos_ppc64le[] = {
    POWERPC_REGS
};

static_assert((sizeof(g_register_infos_ppc64le) /
               sizeof(g_register_infos_ppc64le[0])) ==
                  k_num_registers_ppc64le,
              "g_register_infos_powerpc64 has wrong number of register infos");

#undef DEFINE_FPR
#undef DEFINE_GPR

#endif // DECLARE_REGISTER_INFOS_PPC64LE_STRUCT
