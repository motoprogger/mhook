// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
//
// WARNING:
// I wouldn't recommend changing any flags like OP_*, ITYPE_*, or *_MASK
// aside from those marked as UNUSED. This is because the flags parts of
// the flags are architecture independent and other are left to specific
// architectures to define, so unless you understand the relationships
// between them, I would leave them as is.

#ifndef DISASM_H
#define DISASM_H
#ifdef __cplusplus
extern "C" {
#endif
#include <windows.h>
#include <stdio.h>
#include "misc.h"
#include "disasm_types.h"

#ifdef SPEEDY
// On Visual Studio 6, making the internal functions inline makes compiling take forever
#define INTERNAL static _inline 
#define INLINE _inline
#else
#define INTERNAL static
#define INLINE
#endif

#include "disasm_x86.h"

struct _INSTRUCTION {
    U32 Initialized;
    struct _DISASSEMBLER *Disassembler;

    char String[MAX_OPCODE_DESCRIPTION];
    U8 StringIndex;
    U64 VirtualAddressDelta;

    U32 Groups; // ITYPE_EXEC, ITYPE_ARITH, etc. -- NOTE groups can be OR'd together
    INSTRUCTION_TYPE Type; // ITYPE_ADD, ITYPE_RET, etc. -- NOTE there is only one possible type

    U8 *Address;
    U8 *OpcodeAddress;
    U32 Length;

    U8 Prefixes[MAX_PREFIX_LENGTH];
    U32 PrefixCount;

    U8 LastOpcode; // last byte of opcode
    U8 OpcodeBytes[MAX_OPCODE_LENGTH];
    U32 OpcodeLength; // excludes any operands and prefixes

    INSTRUCTION_OPERAND Operands[MAX_OPERAND_COUNT];
    U32 OperandCount;

    X86_INSTRUCTION X86;

    DATA_REFERENCE DataSrc;
    DATA_REFERENCE DataDst;
    CODE_BRANCH CodeBranch;

    // Direction depends on which direction the stack grows
    // For example, on x86 a push results in StackChange < 0 since the stack grows down
    // This is only relevant if (Group & ITYPE_STACK) is true
    //
    // If Groups & ITYPE_STACK is set but StackChange = 0, it means that the change
    // couldn't be determined (non-constant)
    LONG StackChange;

    // Used to assist in debugging
    // If set, the current instruction is doing something that requires special handling
    // For example, popf can cause tracing to be disabled

    U8 StringAligned : 1; // internal only
    U8 NeedsEmulation : 1; // instruction does something that re
    U8 Repeat : 1; // instruction repeats until some condition is met (e.g., REP prefix on X86)
    U8 ErrorOccurred : 1; // set if instruction is invalid
    U8 AnomalyOccurred : 1; // set if instruction is anomalous
    U8 LastInstruction : 1; // tells the iterator callback it is the last instruction
    U8 CodeBlockFirst: 1;
    U8 CodeBlockLast : 1;
};

typedef struct _ARCHITECTURE_FORMAT
{
    ARCHITECTURE_TYPE Type;
    ARCHITECTURE_FORMAT_FUNCTIONS *Functions;
} ARCHITECTURE_FORMAT;

typedef struct _DISASSEMBLER
{
    U32 Initialized;
    ARCHITECTURE_TYPE ArchType;
    ARCHITECTURE_FORMAT_FUNCTIONS *Functions;
    INSTRUCTION Instruction;
    U32 Stage1Count; // GetInstruction called
    U32 Stage2Count; // Opcode fully decoded
    U32 Stage3CountNoDecode;   // made it through all checks when DISASM_DECODE is not set
    U32 Stage3CountWithDecode; // made it through all checks when DISASM_DECODE is set
} DISASSEMBLER;

#define DISASM_DISASSEMBLE         (1<<1)
#define DISASM_DECODE              (1<<2)
#define DISASM_SUPPRESSERRORS      (1<<3)
#define DISASM_SHOWFLAGS           (1<<4)
#define DISASM_ALIGNOUTPUT         (1<<5)
#define DISASM_DISASSEMBLE_MASK (DISASM_ALIGNOUTPUT|DISASM_SHOWBYTES|DISASM_DISASSEMBLE)

BOOL InitDisassembler(DISASSEMBLER *Disassembler, ARCHITECTURE_TYPE Architecture);
void CloseDisassembler(DISASSEMBLER *Disassembler);
INSTRUCTION *GetInstruction(DISASSEMBLER *Disassembler, U64 VirtualAddress, U8 *Address, U32 Flags);

#ifdef __cplusplus
}
#endif
#endif // DISASM_H
