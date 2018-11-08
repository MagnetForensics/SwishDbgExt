/*++
    Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2014 MoonSols Ltd.
    Copyright (C) 2014 Matthieu Suiche (@msuiche)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Module Name:

    - Security.cpp

Abstract:

    - Thanks to Frank Boldewin for sharing his code.

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"


const char *Blacklist_Functions[] = {
    "UrlDownloadToFile",
    "GetTempPath",
    "GetWindowsDirectory",
    "GetSystemDirectory",
    "WinExec",
    "ShellExecute",
    "IsBadReadPtr",
    "IsBadWritePtr",
    "CreateFile",
    "CloseHandle",
    "ReadFile",
    "WriteFile",
    "SetFilePointer",
    "VirtualAlloc",
    "GetProcAddr",
    "LoadLibrary",
    NULL
};

typedef struct _PATTERN_DATA {
    BOOLEAN Initialized;
    ULONG PatternBitMask;
    UCHAR Pattern[12]; // Max Size 12
} PATTERN_DATA, *PPATTERN_DATA;

typedef void (CALLBACK *DISPLAY_CALLBACK)(_In_ BOOLEAN Verbose, _In_ ULONG64 Base, _In_ ULONG Offset);

typedef struct _PATTERN_ENTRY {
    ULONG Type;
    CHAR *Pattern;
    ULONG PatternSize;

    DISPLAY_CALLBACK CallbackRoutine;

    PATTERN_DATA Data; // PatternCustomType only
} PATTERN_ENTRY, *PPATTERN_ENTRY;

typedef enum _PATTERN_TYPE {
    PatternNoneType = 0,
    PatternDataType = 1,
    PatternCustomType = 2
} PATTERN_TYPE;

#define InitPattern(a) {PatternDataType, a, sizeof(a) - 1, NULL, {FALSE, 0, 0}}
#define InitCustomPattern(a) {PatternCustomType, a, 1, NULL, {FALSE, 0, 0}}

#define InitPatternEx(a, b) {PatternDataType, a, sizeof(a) - 1, b, {FALSE, 0, 0}}
#define InitCustomPatternEx(a, b) {PatternCustomType, a, 1, b, {FALSE, 0, 0}}

PATTERN_ENTRY g_PatternLoop[] = {
    InitPattern("\x80\x30"),
    InitPattern("\x80\x31"),
    InitPattern("\x80\x32"),
    InitPattern("\x80\x33"),
    InitPattern("\x80\x34"),
    InitPattern("\x80\x74"),
    InitPattern("\x81\x70"),
    InitPattern("\x81\x71"),
    InitPattern("\x81\x72"),
    InitPattern("\x81\x73"),
    InitPattern("\x81\xF0"),
    InitPattern("\x81\xF2"),
    InitPattern("\x81\xF3"),
    InitPattern("\x81\xF6"),
    InitPattern("\x81\xF7"),
    InitPattern("\xC0\xC0"),
    InitPattern("\xC0\xC1"),
    InitPattern("\xC0\xC2"),
    InitPattern("\xC0\xC3"),
    InitPattern("\x30\x04\x0A"),
    InitPattern("\x30\x04\x0B"),
    InitPattern("\x30\x04\x0E"),
    InitPattern("\x30\x04\x0F"),
    InitPattern("\x30\x04\x11"),
    InitPattern("\x30\x04\x19"),
    InitPattern("\x30\x04\x1A"),
    InitPattern("\x30\x04\x31"),
    InitPattern("\x30\x04\x39"),
    InitPattern("\x35"),

    { 0 }
};

// check for xor ecx,ecx  or  mov ecx, [esp] or mov ecx, 0xnnnnnn00
PATTERN_ENTRY g_InitEcx[] = {
    InitPattern("\x33\xC9"),
    InitPattern("\x31\xC9"),
    InitPattern("\x8B\x0C\x24"),
    InitPattern("\xB9\x00"),

    { 0 }
};

VOID
CALLBACK
call_pop_signature_callback(
    BOOLEAN Verbose,
    ULONG64 Base,
    ULONG Offset
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    Base - 
    Offset - 

Return Value:

    None.

--*/
{
    ULONG64 Va = SIGN_EXTEND(Base + Offset);
    if (Verbose) g_Ext->Dml("    CALL next/POP signature @ <link cmd=\"u 0x%I64X\">0x%llX</link> [offset = 0x%x]\n", Va, Va, Offset);
}

VOID
CALLBACK
fpu_signature_callback(
    BOOLEAN Verbose,
    ULONG64 Base,
    ULONG Offset
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    Base - 
    Offset -

Return Value:

    None.

--*/
{
    ULONG64 Va = SIGN_EXTEND(Base + Offset);
    if (Verbose) g_Ext->Dml("    FLDZ/FSTENV [esp-12] signature @ <link cmd=\"u 0x%I64X\">0x%llX</link> [offset = 0x%x]\n", Va, Va, Offset);
}

VOID
CALLBACK
push_call_signature_callback(
    BOOLEAN Verbose,
    ULONG64 Base,
    ULONG Offset
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    Base -
    Offset -

Return Value:

    None.

--*/
{
    ULONG64 Va = SIGN_EXTEND(Base + Offset);
    if (Verbose) g_Ext->Dml("    PUSH DWORD[]/CALL[] signature @ <link cmd=\"u 0x%I64X\">0x%llX</link> [offset = 0x%x]\n", Va, Va, Offset);
}

VOID
CALLBACK
function_prolog_signature_callback(
    BOOLEAN Verbose,
    ULONG64 Base,
    ULONG Offset
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    Base -
    Offset -

Return Value:

    None.

--*/
{
    ULONG64 Va = SIGN_EXTEND(Base + Offset);
    if (Verbose) g_Ext->Dml("    Function prolog signature @ <link cmd=\"u 0x%I64X\">0x%llX</link> [offset = 0x%x]\n", Va, Va, Offset);
}

VOID
CALLBACK
api_hashing_signature_callback(
    BOOLEAN Verbose,
    ULONG64 Base,
    ULONG Offset
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    Base -
    Offset -

Return Value:

    None.

--*/
{
    ULONG64 Va = SIGN_EXTEND(Base + Offset);
    if (Verbose) g_Ext->Dml("    API-Hashing signature @ <link cmd=\"u 0x%I64X\">0x%llX</link> [offset = 0x%x]\n", Va, Va, Offset);
}

VOID
CALLBACK
peb2_access_signature_callback(
    BOOLEAN Verbose,
    ULONG64 Base,
    ULONG Offset
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    Base -
    Offset -

Return Value:

    None.

--*/
{
    ULONG64 Va = SIGN_EXTEND(Base + Offset);
    if (Verbose) g_Ext->Dml("    FS:[00h] signature @ <link cmd=\"u 0x%I64X\">0x%llX</link> [offset = 0x%x]\n", Va, Va, Offset);
}

VOID
CALLBACK
peb_access_signature_callback(
    BOOLEAN Verbose,
    ULONG64 Base,
    ULONG Offset
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    Base -
    Offset -

Return Value:

    None.

--*/
{
    ULONG64 Va = SIGN_EXTEND(Base + Offset);
    if (Verbose) g_Ext->Dml("    FS:[30h] signature @ <link cmd=\"u 0x%I64X\">0x%llX</link> [offset = 0x%x]\n", Va, Va, Offset);
}

PATTERN_ENTRY g_PatternTable[] = {
    // FS:[30h] signature
    InitPatternEx("\x64\xA1\x30\x00\x00", peb_access_signature_callback),
    InitPatternEx("\x64\x8B\x40\x30", peb_access_signature_callback),
    InitPatternEx("\x64\x8B\x1D\x30\x00", peb_access_signature_callback),
    InitPatternEx("\x64\x8B\x0D\x30\x00", peb_access_signature_callback),
    InitPatternEx("\x64\x8B\x15\x30\x00", peb_access_signature_callback),
    InitPatternEx("\x64\x8B\x35\x30\x00", peb_access_signature_callback),
    InitPatternEx("\x64\x8B\x3D\x30\x00", peb_access_signature_callback),
    InitPatternEx("\x67\x64\xA1\x30\x00", peb_access_signature_callback),

    InitCustomPatternEx("6a30??648b", peb_access_signature_callback),
    InitCustomPatternEx("33????b3648b", peb_access_signature_callback),
    InitCustomPatternEx("6a8b??308b", peb_access_signature_callback),

    InitPatternEx("\x64\xFF\x35\x30", peb_access_signature_callback),

    // FS:[00h] signature found
    InitPatternEx("\x64\xA1\x00\x00\x00", peb2_access_signature_callback),
    InitPatternEx("\x64\x8B\x1D\x00\x00", peb2_access_signature_callback),
    InitPatternEx("\x64\x8B\x0D\x00\x00", peb2_access_signature_callback),
    InitPatternEx("\x64\x8B\x15\x00\x00", peb2_access_signature_callback),
    InitPatternEx("\x64\x8B\x35\x00\x00", peb2_access_signature_callback),
    InitPatternEx("\x64\x8B\x3D\x00\x00", peb2_access_signature_callback),

    // API-Hashing signature

    InitCustomPatternEx("74??c1??0d", api_hashing_signature_callback),
    InitCustomPatternEx("74??c1??07", api_hashing_signature_callback),
    InitCustomPatternEx("74??c1??0b03", api_hashing_signature_callback),

    // Function prolog signature

    InitPatternEx("\x55\x8b\xec\x83\xc4", function_prolog_signature_callback),

    InitPatternEx("\x55\x8b\xec\x81\xec", function_prolog_signature_callback),
    InitPatternEx("\x55\x8b\xec\xeb", function_prolog_signature_callback),
    InitPatternEx("\x55\x8b\xec\xe8", function_prolog_signature_callback),
    InitPatternEx("\x55\x8b\xec\xe9", function_prolog_signature_callback),

    // PUSH DWORD[]/CALL[] signature

    InitCustomPatternEx("ff75??ff55", push_call_signature_callback),
    InitCustomPatternEx("ff77??ff57", push_call_signature_callback),
    InitCustomPatternEx("ffb7????????ff57", push_call_signature_callback),

    // FLDZ/FSTENV [esp-12] signature
    InitPatternEx("\xD9\xEE\xD9\x74\x24\xF4", fpu_signature_callback),

    InitPatternEx("\xD9\x74\x24\xF4\x58", fpu_signature_callback),
    InitPatternEx("\xD9\x74\x24\xF4\x59", fpu_signature_callback),
    InitPatternEx("\xD9\x74\x24\xF4\x5a", fpu_signature_callback),
    InitPatternEx("\xD9\x74\x24\xF4\x5b", fpu_signature_callback),

    // CALL next/POP signature
    InitPatternEx("\xE8\x00\x00\x00\x00\x58", call_pop_signature_callback),
    InitPatternEx("\xE8\x00\x00\x00\x00\x59", call_pop_signature_callback),
    InitPatternEx("\xE8\x00\x00\x00\x00\x5A", call_pop_signature_callback),
    InitPatternEx("\xE8\x00\x00\x00\x00\x5B", call_pop_signature_callback),
    InitPatternEx("\xE8\x00\x00\x00\x00\x5E", call_pop_signature_callback),
    InitPatternEx("\xE8\x00\x00\x00\x00\x5F", call_pop_signature_callback),

    InitPatternEx("\xE8\x00\x00\x00\x00\x5D", call_pop_signature_callback),

    { 0 }
};

ULONG
GetMaxPatternLen(
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    ULONG.

--*/
{
    ULONG MaxLen = 0;

    for (UINT i = 0; g_PatternTable[i].PatternSize; i += 1)
    {
        if (g_PatternTable[i].PatternSize > MaxLen) MaxLen = g_PatternTable[i].PatternSize;
    }

    return MaxLen;
}

ULONG
GetMaxBlacklistedLen(
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    ULONG.

--*/
{
    ULONG MaxLen = 0;

    for (UINT i = 0; Blacklist_Functions[i]; i += 1)
    {
        ULONG Len = (ULONG)strlen(Blacklist_Functions[i]);
        if (Len > MaxLen) MaxLen = Len;
    }

    return MaxLen;
}

BOOLEAN
InitPatternTable(
    _Inout_ PPATTERN_ENTRY PatternTable
)
/*++

Routine Description:

    Description.

Arguments:

   PatternTable -

Return Value:

    BOOLEAN.

--*/
{
    for (UINT i = 0; PatternTable[i].PatternSize; i += 1)
    {
        if ((PatternTable[i].Type == PatternCustomType) && (PatternTable[i].Data.Initialized == FALSE))
        {
            UINT j;
            ULONG Len = (ULONG)strlen(PatternTable[i].Pattern);

            for (j = 0; j < Len / 2; j += 1)
            {
                if (memcmp(&PatternTable[i].Pattern[2 * j], "??", 2) != 0)
                {
                    sscanf_s(&PatternTable[i].Pattern[2 * j], "%02x", (PUINT)&PatternTable[i].Data.Pattern[j]);
                    // g_Ext->Dml("PatternTable[i].Data.Pattern[%d] = 0x%x\n", j, PatternTable[i].Data.Pattern[j]);
                    PatternTable[i].Data.PatternBitMask |= (1 << j);
                }
                else
                {
                    PatternTable[i].Data.Pattern[j] = 0;
                }
            }

            PatternTable[i].PatternSize = j;
            PatternTable[i].Data.Initialized = TRUE;

            // g_Ext->Dml("Len = %d, Mask = 0x%x\n", j, PatternTable[i].Data.PatternBitMask);
        }
    }

    return TRUE;
}

BOOLEAN
MatchPattern(
    _In_ BOOLEAN Verbose,
    _In_ PUCHAR Input,
    _In_ ULONG64 VirtualAddress,
    _In_ ULONG Offset,
    _In_ PPATTERN_ENTRY PatternTable
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose -
    Input - 
    VirtualAddress -
    Offset -
    PatternTable - 

Return Value:

    BOOLEAN.

--*/
{
    BOOLEAN Matched = FALSE;

    for (UINT i = 0; PatternTable[i].PatternSize; i += 1)
    {
        if (PatternTable[i].Type == PatternDataType)
        {
            if (memcmp(PatternTable[i].Pattern, Input, PatternTable[i].PatternSize) == 0)
            {
                Matched = TRUE;
                if (PatternTable[i].CallbackRoutine)
                {
                    // g_Ext->Dml("DataLen = %d, Signature Id = %d\n", PatternTable[i].PatternSize, i);
                    PatternTable[i].CallbackRoutine(Verbose, VirtualAddress, Offset);
                }

                break;
            }
        }
        else if ((PatternTable[i].Type == PatternCustomType) && PatternTable[i].Data.Initialized)
        {
            UINT j;
            for (j = 0; j < PatternTable[i].PatternSize; j += 1)
            {
                if (PatternTable[i].Data.PatternBitMask & (1 << j))
                {
                    if (PatternTable[i].Data.Pattern[j] != Input[j]) break;
                }
            }

            if ((j == PatternTable[i].PatternSize) && (PatternTable[i].Data.PatternBitMask))
            {
                Matched = TRUE;

                if (PatternTable[i].CallbackRoutine)
                {
                    // g_Ext->Dml("Custom::DataLen = %d, Signature Id = %d, BitMask = %x\n", PatternTable[i].PatternSize, i, PatternTable[i].Data.PatternBitMask);
                    PatternTable[i].CallbackRoutine(Verbose, VirtualAddress, Offset);
                }
                break;
            }
        }
    }

    return Matched;
}

ULONG
GetMalScore(
    BOOLEAN Verbose,
    ULONG64 VirtualAddress,
    LPBYTE Buffer,
    ULONG BufferLen
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose - 
    VirtualAddress -
    Buffer -
    BufferLen - 

Return Value:

    ULONG.

--*/
{
    ULONG i;
    ULONG64 val = 0, val2 = 0, addr = 0;

    InitPatternTable(g_PatternTable);
    ULONG MaxPatternLen = GetMaxPatternLen();

    //ULONG MaxBlLen = GetMaxBlacklistedLen();

    UINT MalScoreIndex = 0;

    BOOLEAN bHeapSpray = FALSE;

    for (UINT a = 0; a < BufferLen - MaxPatternLen; a++)
    {
        if (MatchPattern(Verbose, Buffer + a, VirtualAddress, a, g_PatternTable))
        {
            MalScoreIndex = MalScoreIndex + 10;
        }
        else if (Buffer[a] == 0xEB && (Buffer[a + 1] < BufferLen) && Buffer[a + 2 + Buffer[a + 1]] == 0xE8) // JMP + CALL
        {
            // addr = (DWORD)((Buffer + a + 2 + *(Buffer + a + 1)) - Buffer);
            addr = a + 2 + Buffer[a + 1];
            val = (Buffer[addr + 1]) | (Buffer[addr + 2] << 8) | (Buffer[addr + 3] << 16) | (Buffer[addr + 4] << 24);

            if ((addr + val + 5) >= BufferLen) continue; // Invalid range

            switch (Buffer[addr + val + 5])
            {
            case 0x58:
            case 0x59:
            case 0x5A:
            case 0x5B:
                if (Verbose) g_Ext->Dml("    JMP [0xEB]/CALL/POP signature found @ <link cmd=\"u 0x%I64X\">0x%X</link>\n",
                                        VirtualAddress + a, a);
                // if (DEBUG == 1) Disasm(Buffer + a);
                MalScoreIndex = MalScoreIndex + 10;
                break;

            case 0x5E:
            case 0x5f:
                if (Verbose) g_Ext->Dml("    JMP [0xEB]/CALL/POP signature found @ <link cmd=\"u 0x%I64X\">0x%X</link>\n",
                    VirtualAddress + a, a);
                // if (DEBUG == 1) Disasm(Buffer + a);
                MalScoreIndex = MalScoreIndex + 10;
                break;

            case 0x33:
            case 0xc9:
                if (Verbose) g_Ext->Dml("    JMP [0xEB]/CALL signature found @ <link cmd=\"u 0x%I64X\">0x%X</link>\n",
                    VirtualAddress + a, a);
                // if (DEBUG == 1) Disasm(Buffer + a);
                MalScoreIndex = MalScoreIndex + 10;
                break;
            }
        }
        else if (Buffer[a] == 0xE9)
        {
            val = (Buffer[a + 1]) | (Buffer[a + 2] << 8) | (Buffer[a + 3] << 16) | (Buffer[a + 4] << 24);

            if ((a + val + 5) >= BufferLen) continue; // Invalid range

            if (Buffer[a + val + 5] == 0xE8)
            {
                val2 = (Buffer[a + val + 1]) | (Buffer[a + val + 2] << 8) | (Buffer[a + val + 3] << 16) | (Buffer[a + val + 4] << 24);

                char Opcode = 0;
                if (val2 == 0)
                {
                    if ((a + val + 5 + 5) >= BufferLen) continue; // Invalid range

                    Opcode = Buffer[a + val + 5 + 5];
                }
                else
                {
                    val2 ^= 0xffffffff;

                    if ((a + val + 5 - val2 + 4) >= BufferLen) continue; // Invalid range

                    Opcode = Buffer[a + val + 5 - val2 + 4];
                }

                switch (Opcode)
                {
                case 0x58:
                case 0x59:
                case 0x5A:
                case 0x5B:
                    if (Verbose) g_Ext->Dml("    JMP [0xE9]/CALL/POP signature found @ <link cmd=\"u 0x%I64X\">0x%X</link>\n",
                        VirtualAddress + a, a);
                    // if (DEBUG == 1) Disasm(Buffer + a);
                    MalScoreIndex = MalScoreIndex + 10;
                    break;

                case 0x5D:
                case 0x5E:
                case 0x5F:
                    if (Verbose) g_Ext->Dml("    JMP [0xE9]/CALL/POP signature found @ <link cmd=\"u 0x%I64X\">0x%X</link>\n",
                        VirtualAddress + a, a);
                    // if (DEBUG == 1) Disasm(Buffer + a);
                    MalScoreIndex = MalScoreIndex + 10;
                    break;
                }
            }
        }
        else if ((Buffer[a] == 0x75) || (Buffer[a] == 0xE2) || (Buffer[a] == 0x72))
        {
            unsigned int loopinitstart = 0, p = 0, r = 0, loinitdist = 0x20;
            BYTE LO = 0;
            unsigned long base = 0, lostart = 0;

            base = a; //  address of loop opcode
            LO = *(Buffer + a + 1) + 1;
            LO ^= 0xff; // loop length
            lostart = base - LO; // address of loop start

            // is loop length not longer 0x30 ?
            if ((LO < 0x30) && (base > LO))
            {
                // loinitdist is the distance length from lostart. from here we scan 0x20 bytes for a loop init via ECX
                for (p = 0; p <= loinitdist; p++)
                {
                    if (MatchPattern(Verbose, Buffer + lostart - loinitdist + p, VirtualAddress, lostart - loinitdist + p, g_InitEcx))
                    {
                        // variable loopinitstart stores start of loop init via ECX register
                        loopinitstart = p;

                        for (r = 0; r <= LO; r++)
                        {
                            // scan for several XORs and ROLs (ADD missing currently)
                            if (MatchPattern(Verbose, Buffer + base - LO + r, VirtualAddress, base - LO + r, g_PatternLoop))
                            {
                                if (Verbose) g_Ext->Dml("    Decryption loop detected at offset <link cmd=\"u 0x%I64X\">0x%08x</link>\n\n",
                                                        VirtualAddress + lostart - loinitdist + loopinitstart,
                                                        lostart - loinitdist + loopinitstart);
                                // Disasm(Buffer + lostart - loinitdist + loopinitstart);
                                // if (Verbose) g_Ext->Dml("<link cmd=\"u 0x%I64X\">Disass detected loop @ 0x%X</link>\n", VirtualAddress + lostart - loinitdist + loopinitstart);
                                MalScoreIndex = MalScoreIndex + 10;
                                a = base + 2;
                                break;
                            }
                        }
                    }
                }
            }
        }
        else if (Buffer[a] == 0x90)
        {
            ULONG PatternLength = 0x900;
            for (i = 0; i < PatternLength; i += 1)
            {
                if (Buffer[a + i] != 0x90) break;
            }

            if (i == PatternLength)
            {
                if (Verbose && !bHeapSpray)
                {
                    g_Ext->Dml("    Heap-spray signature detected @ <link cmd=\"u 0x%I64X\">0x%X</link>\n", VirtualAddress + a, a);
                    bHeapSpray = TRUE;
                }
                MalScoreIndex += 2000;
                a += i;
            }
        }
        else
        {
            for (i = 0; Blacklist_Functions[i]; i++)
            {
                if (memcmp(Blacklist_Functions[i], Buffer + a, strlen(Blacklist_Functions[i])) == 0)
                {
                    if (Verbose) g_Ext->Dml("    API-Name \"%s\" string found at offset: 0x%x\n", Blacklist_Functions[i], a);
                    // if (DEBUG == 1) HexDump("PE-File", Buffer + a, 256);
                    MalScoreIndex = MalScoreIndex + 2;
                }
            }
        }
    }

    return MalScoreIndex;
}

ULONG
GetMalScoreEx(
    BOOLEAN Verbose,
    MsProcessObject *ProcObj,
    ULONG64 BaseAddress,
    ULONG Length
)
/*++

Routine Description:

    Description.

Arguments:

    Verbose -
    ProcObj -
    BaseAddress -
    Length -

Return Value:

    ULONG.

--*/
{
    PBYTE Buffer = NULL;
    ULONG MalScore = 0;

    if (!Length) {

        return 0;
    }

    Buffer = (PBYTE)calloc(Length, sizeof(BYTE));

    if (Buffer) {

        if (ProcObj) ProcObj->SwitchContext();

        if (ExtRemoteTypedEx::ReadVirtual(BaseAddress, Buffer, Length, NULL) == S_OK) {

            MalScore = GetMalScore(Verbose, BaseAddress, Buffer, Length);
        }

        if (ProcObj) ProcObj->RestoreContext();

        free(Buffer);
    }

    return MalScore;
}

BOOLEAN
IsImageInMemoryEx(
    MsProcessObject *ProcObj,
    ULONG64 Offset,
    PUSHORT Sig
) {
    BOOLEAN Status = FALSE;

    if (ProcObj) ProcObj->SwitchContext();

    Status = IsImageInMemory(Offset, Sig);

    if (ProcObj) ProcObj->RestoreContext();

    return Status;
}

BOOLEAN
IsImageInMemory(
    ULONG64 Offset,
    PUSHORT Sig

) {
    UCHAR Data[0x100] = { 0 };
    ULONG BytesRead = 0;

    BOOLEAN Status = FALSE;

    if (g_Ext->m_Data->ReadVirtual(Offset, Data, sizeof(Data), &BytesRead) == S_OK) {

        USHORT Signature = *(PUSHORT)Data;
        if (Sig) *Sig = Signature;

        if (Signature == IMAGE_DOS_SIGNATURE) {
            Status = TRUE;
        }
        else if (memcmp(&Data[0x4e], "Is this program", strlen("Is this program")) == 0) {
            Status = TRUE;
        }
        else if (memcmp(&Data[0x4e], "This program cannot be run", strlen("This program cannot be run")) == 0) {
            Status = TRUE;
        }
    }

    return Status;
}

ULONG64
GetPteFromAddress(
    ULONG64 Va
) {
    ULONG Levels = 0;

    ULONG64 Tables[10];

    HRESULT Result = g_Ext->m_Data3->GetVirtualTranslationPhysicalOffsets(Va, Tables, 10, &Levels);
    if (Result != S_OK) return FALSE;

    ULONG64 PteAddress = Tables[Levels - 2];
    ULONG64 PteEntry = 0;
    Result = g_Ext->m_Data3->ReadPhysical(PteAddress, &PteEntry, sizeof(ULONG64), NULL);

    return PteEntry;
}