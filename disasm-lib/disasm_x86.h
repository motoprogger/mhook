// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
#ifndef X86_DISASM_H
#define X86_DISASM_H
#ifdef __cplusplus
extern "C" {
#endif

#include "disasm_x86_types.h"

////////////////////////////////////////////////////////////////////////////////////
// Exported functions
////////////////////////////////////////////////////////////////////////////////////

extern ARCHITECTURE_FORMAT_FUNCTIONS X86;

// Instruction setup
BOOL X86_InitInstruction(struct _INSTRUCTION *Instruction);
void X86_CloseInstruction(struct _INSTRUCTION *Instruction);

// Instruction translator
BOOL X86_TranslateInstruction(struct _INSTRUCTION *Instruction, BOOL Verbose);

// Instruction decoder
BOOL X86_GetInstruction(struct _INSTRUCTION *Instruction, U8 *Address, DWORD Flags);

// Function finding
U8 *X86_FindFunctionByPrologue(struct _INSTRUCTION *Instruction, U8 *StartAddress, U8 *EndAddress, DWORD Flags);

#ifdef __cplusplus
}
#endif
#endif // X86_DISASM_H

