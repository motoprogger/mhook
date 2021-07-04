// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
#ifndef DISASM_TYPES_H
#define DISASM_TYPES_H
#ifdef __cplusplus
extern "C" {
#endif

typedef signed char S8;
typedef unsigned char U8;
typedef signed short S16;
typedef unsigned short U16;
typedef signed long S32;
typedef unsigned long U32;
typedef LONG64 S64;
typedef ULONG64 U64;
typedef struct DECLSPEC_ALIGN(16) _S128
{
    U64 Low;
    S64 High;
} S128;
typedef struct DECLSPEC_ALIGN(16) _U128
{
    U64 Low;
    U64 High;
} U128;
#define VALID_INSTRUCTION(i) ((i) && !((i)->ErrorOccurred))
#define NEXT_INSTRUCTION(i) ((i)->Address + (i)->Length)
#define DISASM_ARCH_TYPE(dis) ((dis)->ArchType)
#define INS_ARCH_TYPE(ins) DISASM_ARCH_TYPE((ins)->Disassembler)

// NOTE: these should be as big set to the maximum of the supported architectures
#define MAX_PREFIX_LENGTH 15
#define MAX_OPERAND_COUNT 3
#define MAX_INSTRUCTION_LENGTH 25
#define MAX_OPCODE_LENGTH 3
#define MAX_OPCODE_DESCRIPTION 256

/////////////////////////////////////////////////////////////////////
// Code branch
/////////////////////////////////////////////////////////////////////

#define MAX_CODE_REFERENCE_COUNT 3

typedef struct _CODE_BRANCH
{
    U64 Addresses[MAX_CODE_REFERENCE_COUNT]; // NULL if multiple to addresses
    U32 Count;
    U8 IsLoop : 1;
    U8 IsCall : 1; // branch if false
    U8 IsIndirect : 1; // call/jmp [Address]
    U8 AddressOffset: 5;
    struct _INSTRUCTION_OPERAND *Operand; // the operand containg the address
} CODE_BRANCH;

/////////////////////////////////////////////////////////////////////
// Data references
/////////////////////////////////////////////////////////////////////

#define MAX_DATA_REFERENCE_COUNT 3

typedef struct _DATA_REFERENCE
{
    U64 Addresses[MAX_DATA_REFERENCE_COUNT]; // NULL if multiple to addresses
    U32 Count;
    ULONG_PTR DataSize;
    struct _INSTRUCTION_OPERAND *Operand; // the operand containg the address
} DATA_REFERENCE;

////////////////////////////////////////////////////////////////////
// Instruction
/////////////////////////////////////////////////////////////////////

//
// Instruction types (bits 0-7)
// Instruction groups (bits 8-26)
//
#define ITYPE_EXEC_OFFSET     (1<<8)
#define ITYPE_ARITH_OFFSET    (1<<9)
#define ITYPE_LOGIC_OFFSET    (1<<10)
#define ITYPE_STACK_OFFSET    (1<<11)
#define ITYPE_TESTCOND_OFFSET (1<<12)
#define ITYPE_LOAD_OFFSET     (1<<13)
#define ITYPE_ARRAY_OFFSET    (1<<14)
#define ITYPE_BIT_OFFSET      (1<<15)
#define ITYPE_FLAG_OFFSET     (1<<16)
#define ITYPE_FPU_OFFSET      (1<<17)
#define ITYPE_TRAPS_OFFSET    (1<<18)
#define ITYPE_SYSTEM_OFFSET   (1<<19)
#define ITYPE_OTHER_OFFSET    (1<<20)
#define ITYPE_UNUSED1_OFFSET  (1<<21)
#define ITYPE_UNUSED2_OFFSET  (1<<22)
#define ITYPE_UNUSED3_OFFSET  (1<<23)
#define ITYPE_UNUSED4_OFFSET  (1<<24)
#define ITYPE_UNUSED5_OFFSET  (1<<25)
#define ITYPE_UNUSED6_OFFSET  (1<<26)
#define ITYPE_EXT_UNUSED1     (1<<27)
#define ITYPE_EXT_UNUSED2     (1<<28)
#define ITYPE_EXT_UNUSED3     (1<<29)
#define ITYPE_EXT_UNUSED4     (1<<30)
#define ITYPE_EXT_UNUSED5     (1<<31)

//
// X86-specific flags (bits 27-31)
//

#define ITYPE_EXT_64     ITYPE_EXT_UNUSED1 // Use index 1 if in 64-bit mode and 0 otherwise
#define ITYPE_EXT_MODRM  ITYPE_EXT_UNUSED2 // ModRM byte may extend the opcode
#define ITYPE_EXT_SUFFIX ITYPE_EXT_UNUSED3 // byte after ModRM/SIB/displacement is the third opcode
#define ITYPE_EXT_PREFIX ITYPE_EXT_UNUSED4 // prefix
#define ITYPE_EXT_FPU    ITYPE_EXT_UNUSED5 // FPU instructions require special handling

#define ITYPE_3DNOW_OFFSET ITYPE_UNUSED1_OFFSET
#define ITYPE_MMX_OFFSET   ITYPE_UNUSED2_OFFSET
#define ITYPE_SSE_OFFSET   ITYPE_UNUSED3_OFFSET
#define ITYPE_SSE2_OFFSET  ITYPE_UNUSED4_OFFSET
#define ITYPE_SSE3_OFFSET  ITYPE_UNUSED5_OFFSET

//
// Instruction types
//

#define ITYPE_TYPE_MASK  0x7FFFFFFF
#define ITYPE_GROUP_MASK 0x7FFFFF00

typedef enum _INSTRUCTION_TYPE
{
    // ITYPE_EXEC group
    ITYPE_EXEC = ITYPE_EXEC_OFFSET,
    ITYPE_BRANCH,
    ITYPE_BRANCHCC, // conditional (not necessarily just flags)
    ITYPE_CALL,
    ITYPE_CALLCC, // conditional (not necessarily just flags)
    ITYPE_RET,
    ITYPE_LOOPCC,

    // ITYPE_ARITH group
    ITYPE_ARITH = ITYPE_ARITH_OFFSET,
    ITYPE_XCHGADD,
    ITYPE_ADD,
    ITYPE_SUB,
    ITYPE_MUL,
    ITYPE_DIV,
    ITYPE_INC,
    ITYPE_DEC,
    ITYPE_SHL,
    ITYPE_SHR,
    ITYPE_ROL,
    ITYPE_ROR,

    // ITYPE_LOGIC group
    ITYPE_LOGIC=ITYPE_LOGIC_OFFSET,
    ITYPE_AND,
    ITYPE_OR,
    ITYPE_XOR,
    ITYPE_NOT,
    ITYPE_NEG,

    // ITYPE_STACK group
    ITYPE_STACK=ITYPE_STACK_OFFSET,
    ITYPE_PUSH,
    ITYPE_POP,
    ITYPE_PUSHA,
    ITYPE_POPA,
    ITYPE_PUSHF,
    ITYPE_POPF,
    ITYPE_ENTER,
    ITYPE_LEAVE,

    // ITYPE_TESTCOND group
    ITYPE_TESTCOND=ITYPE_TESTCOND_OFFSET,
        ITYPE_TEST,
        ITYPE_CMP,

    // ITYPE_LOAD group
    ITYPE_LOAD=ITYPE_LOAD_OFFSET,
        ITYPE_MOV,
        ITYPE_MOVCC, // conditional
        ITYPE_LEA,
        ITYPE_XCHG,
        ITYPE_XCHGCC, // conditional

    // ITYPE_ARRAY group
    ITYPE_ARRAY=ITYPE_ARRAY_OFFSET,
        ITYPE_STRCMP,
        ITYPE_STRLOAD,
        ITYPE_STRMOV,
        ITYPE_STRSTOR,
        ITYPE_XLAT,

    // ITYPE_BIT group
    ITYPE_BIT=ITYPE_BIT_OFFSET,
        ITYPE_BITTEST,
        ITYPE_BITSET,
        ITYPE_BITCLR,

    // ITYPE_FLAG group
    // PF = parify flag
    // ZF = zero flag
    // OF = overflow flag
    // DF = direction flag
    // SF = sign flag
    ITYPE_FLAG=ITYPE_FLAG_OFFSET,
        // clear
        ITYPE_CLEARCF, 
        ITYPE_CLEARZF,
        ITYPE_CLEAROF,
        ITYPE_CLEARDF,
        ITYPE_CLEARSF,
        ITYPE_CLEARPF,
        // set
        ITYPE_SETCF, 
        ITYPE_SETZF,
        ITYPE_SETOF,
        ITYPE_SETDF,
        ITYPE_SETSF,
        ITYPE_SETPF,
        // toggle
        ITYPE_TOGCF, 
        ITYPE_TOGZF,
        ITYPE_TOGOF,
        ITYPE_TOGDF,
        ITYPE_TOGSF,
        ITYPE_TOGPF,

    // ITYPE_FPU group
    ITYPE_FPU=ITYPE_FPU_OFFSET,
        ITYPE_FADD,
        ITYPE_FSUB,
        ITYPE_FMUL,
        ITYPE_FDIV,
        ITYPE_FCOMP,
        ITYPE_FEXCH,
        ITYPE_FLOAD,
        ITYPE_FLOADENV,
        ITYPE_FSTORE,
        ITYPE_FSTOREENV,
        ITYPE_FSAVE,
        ITYPE_FRESTORE,
        ITYPE_FMOVCC,

    ITYPE_UNUSED1=ITYPE_UNUSED1_OFFSET,
    ITYPE_UNUSED2=ITYPE_UNUSED2_OFFSET,
    ITYPE_UNUSED3=ITYPE_UNUSED3_OFFSET,

    // ITYPE_MMX group
    ITYPE_MMX=ITYPE_MMX_OFFSET,
        ITYPE_MMX_MOV,
        ITYPE_MMX_ADD,
        ITYPE_MMX_SUB,
        ITYPE_MMX_MUL,
        ITYPE_MMX_DIV,
        ITYPE_MMX_AND,
        ITYPE_MMX_OR,
        ITYPE_MMX_XOR,
        ITYPE_MMX_CMP,

    // ITYPE_SSE group
    ITYPE_SSE=ITYPE_SSE_OFFSET,
        ITYPE_SSE_MOV,
        ITYPE_SSE_ADD,
        ITYPE_SSE_SUB,
        ITYPE_SSE_MUL,
        ITYPE_SSE_DIV,
        ITYPE_SSE_AND,
        ITYPE_SSE_OR,
        ITYPE_SSE_XOR,
        ITYPE_SSE_CMP,
        
        // ITYPE_SSE2 group
    ITYPE_SSE2=ITYPE_SSE2_OFFSET,
        ITYPE_SSE2_MOV,
        ITYPE_SSE2_ADD,
        ITYPE_SSE2_SUB,
        ITYPE_SSE2_MUL,
        ITYPE_SSE2_DIV,
        ITYPE_SSE2_AND,
        ITYPE_SSE2_OR,
        ITYPE_SSE2_XOR,
        ITYPE_SSE2_CMP,

    // ITYPE_SSE3 group
    ITYPE_SSE3=ITYPE_SSE3_OFFSET,
        ITYPE_SSE3_MOV,
        ITYPE_SSE3_ADD,
        ITYPE_SSE3_SUB,
        ITYPE_SSE3_MUL,
        ITYPE_SSE3_DIV,
        ITYPE_SSE3_AND,
        ITYPE_SSE3_OR,
        ITYPE_SSE3_XOR,
        ITYPE_SSE3_CMP,

    // ITYPE_3DNOW group
    ITYPE_3DNOW=ITYPE_3DNOW_OFFSET,
        ITYPE_3DNOW_ADD,
        ITYPE_3DNOW_SUB,
        ITYPE_3DNOW_MUL,
        ITYPE_3DNOW_DIV,
        ITYPE_3DNOW_CMP,
        ITYPE_3DNOW_XCHG,

    // ITYPE_TRAP
    ITYPE_TRAPS=ITYPE_TRAPS_OFFSET, 
        ITYPE_TRAP, // generate trap
        ITYPE_TRAPCC,  // conditional trap gen
        ITYPE_TRAPRET,    // return from trap
        ITYPE_BOUNDS,  // gen bounds trap
        ITYPE_DEBUG,   // gen breakpoint trap
        ITYPE_TRACE,   // gen single step trap
        ITYPE_INVALID, // gen invalid instruction
        ITYPE_OFLOW,   // gen overflow trap

    // ITYPE_SYSTEM group
    ITYPE_SYSTEM=ITYPE_SYSTEM_OFFSET,
        ITYPE_HALT,    // halt machine
        ITYPE_IN,      // input form port
        ITYPE_OUT,     // output to port
        ITYPE_CPUID,   // identify cpu
        ITYPE_SETIF,   // allow interrupts
        ITYPE_CLEARIF, // block interrupts
        ITYPE_SYSCALL,
        ITYPE_SYSCALLRET,

    // ITYPE_OTHER group
    ITYPE_OTHER = ITYPE_OTHER_OFFSET,
        ITYPE_NOP,
        ITYPE_BCDCONV, // convert to/from BCD
        ITYPE_SZCONV   // convert size of operand
} INSTRUCTION_TYPE;

//
// Operand flags
//

// Type = bits 0-6 (these are mutually exclusive -- bits 0-6 will always be a power of 2))
#define OPTYPE_NONE    0x00
#define OPTYPE_IMM    0x01 // immediate value
#define OPTYPE_OFFSET 0x02 // relative offset
#define OPTYPE_FLOAT  0x03 // floating point
#define OPTYPE_BCD    0x04
#define OPTYPE_STRING 0x05
#define OPTYPE_SPECIAL 0x06
#define OPTYPE_MASK   0x7F

// Flags = bits 7-23 (these can be combinations)
// These are used in the X86 opcode table
#define OP_REG      (1<<7) // 0x80
#define OP_SIGNED   (1<<8)
#define OP_SYS      (1<<9) // parameter is an index into some system structure
#define OP_CONDR    (1<<10)
#define OP_CONDW    (1<<11)
#define OP_UNUSED   (1<<12)
#define OP_SRC      (1<<13) // operand is source operand
#define OP_DST      (1<<14) // operand is destination operand
#define OP_EXEC     (1<<15) // operand is executed

#define OP_CONDE     OP_CONDR
#define OP_COND_EXEC (OP_CONDE|OP_EXEC) // executed only if the pre-conditions are met
#define OP_COND_SRC  (OP_CONDR|OP_SRC) // set only if pre-conditions are met
#define OP_COND_DST  (OP_CONDW|OP_DST) // set only if pre-conditions are met
#define OP_COND      (OP_CONDR|OP_CONDW)

// Bits 16-31 are available for use outside of the opcode table, but they can only
// be used in INSTRUCTION_OPERAND.Flags, they may conflit with the architecture specific
// operands. For example, bits 16-31 are used in X86 for AMODE_* and OPTYPE_*
#define OP_ADDRESS    (1<<16)
#define OP_LOCAL      (1<<17)
#define OP_PARAM      (1<<18)
#define OP_GLOBAL     (1<<19)
#define OP_FAR        (1<<20)
#define OP_IPREL      (1<<21)

//
// X86-specific flags (bits 27-31)
//
#define OP_MSR      (OP_SYS|OP_UNUSED)

//
// Other architecture flags
//
#define OP_DELAY  OP_UNUSED // delayed instruction (e.g., delayed branch that executes after the next instruction)

/////////////////////////////////////////////////////////////////////
// Architectures
/////////////////////////////////////////////////////////////////////

typedef enum _ARCHITECTURE_TYPE
{
    ARCH_UNKNOWN=0,
    
    // x86-based
    ARCH_X86,    // 32-bit x86
    ARCH_X86_16, // 16-bit x86
    ARCH_X64,    // AMD64 and Intel EMD64
    
    // everything else
    ARCH_ALPHA,
    ARCH_ARM,
    ARCH_DOTNET,
    ARCH_EFI,
    ARCH_IA64,
    ARCH_M68K,
    ARCH_MIPS,
    ARCH_PPC,
    ARCH_SH3,
    ARCH_SH4,
    ARCH_SPARC,
    ARCH_THUMB

} ARCHITECTURE_TYPE;

typedef struct _INSTRUCTION_OPERAND
{
    U32 Flags;
    U8 Type : 6;
    U8 Unused : 2;
    U16 Length;
    

    // If non-NULL, this indicates the target address of the instruction (e.g., a branch or
    // a displacement with no base register). However, this address is only reliable if the
    // image is mapped correctly (e.g., the executable is mapped as an image and fixups have
    // been applied if it is not at its preferred image base).
    //
    // If disassembling a 16-bit DOS application, TargetAddress is in the context of 
    // X86Instruction->Segment. For example, if TargetAddress is the address of a code branch, 
    // it is in the CS segment (unless X86Instruction->HasSegmentOverridePrefix is set). If 
    // TargetAddress is a data pointer, it is in the DS segment (unless 
    // X86Instruction->HasSegmentOverridePrefix is set)
    U64 TargetAddress;
    U32 Register;

    union
    {
        // All 8/16/32-bit operands are extended to 64-bits automatically
        // If you want to downcast, check whether Flags & OP_SIGNED is set
        // Like this:
        // U32 GetOperand32(OPERAND *Operand)
        // {
        //  if (Operand->Flags & OP_SIGNED) return (S32)Operand->Value_S64;
        //  else return (U32)Operand->Value_U64;
        //}
        U64 Value_U64;
        S64 Value_S64;
        U128 Value_U128;
        U128 Float128;
        U8 Float80[80];
        U8 BCD[10];
    };
} INSTRUCTION_OPERAND;

typedef struct _INSTRUCTION INSTRUCTION;

typedef BOOL (*INIT_INSTRUCTION)(INSTRUCTION *Instruction);
typedef void (*DUMP_INSTRUCTION)(INSTRUCTION *Instruction, BOOL ShowBytes, BOOL Verbose);
typedef BOOL (*GET_INSTRUCTION)(INSTRUCTION *Instruction, U8 *Address, U32 Flags);
typedef U8 *(*FIND_FUNCTION_BY_PROLOGUE)(INSTRUCTION *Instruction, U8 *StartAddress, U8 *EndAddress, U32 Flags);

typedef struct _ARCHITECTURE_FORMAT_FUNCTIONS
{
    INIT_INSTRUCTION InitInstruction;
    DUMP_INSTRUCTION DumpInstruction;
    GET_INSTRUCTION GetInstruction;
    FIND_FUNCTION_BY_PROLOGUE FindFunctionByPrologue;
} ARCHITECTURE_FORMAT_FUNCTIONS;

#define DISASSEMBLER_INITIALIZED 0x1234566F
#define INSTRUCTION_INITIALIZED 0x1234567F

#ifdef __cplusplus
}
#endif
#endif // DISASM_TYPES_H

