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

    - Credentials.h

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef __NTDEF_H__
#define __NTDEF_H__

/*
typedef struct _LIST_ENTRY32 {
    ULONG32 Flink;
    ULONG32 Blink;
} LIST_ENTRY32, *PLIST_ENTRY32;
*/

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG32 Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _PEB_LDR_DATA32
{
    /*0x000*/     ULONG32 Length;
    /*0x004*/     UINT8 Initialized;
    /*0x005*/     UINT8 _PADDING0_[0x3];
    /*0x008*/     ULONG32 SsHandle;
    /*0x00C*/     LIST_ENTRY32 InLoadOrderModuleList;
    /*0x014*/     LIST_ENTRY32 InMemoryOrderModuleList;
    /*0x01C*/     LIST_ENTRY32 InInitializationOrderModuleList;
    /*0x024*/     ULONG32 EntryInProgress;
    /*0x028*/     UINT8 ShutdownInProgress;
    /*0x029*/     UINT8 _PADDING1_[0x3];
    /*0x02C*/     ULONG32 ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    /*0x000*/     LIST_ENTRY32 InLoadOrderLinks;
    /*0x008*/     LIST_ENTRY32 InMemoryOrderLinks;
    /*0x010*/     LIST_ENTRY32 InInitializationOrderLinks;
    /*0x018*/     ULONG32 DllBase;
    /*0x01C*/     ULONG32 EntryPoint;
    /*0x020*/     ULONG32 SizeOfImage;
    /*0x024*/     UNICODE_STRING32 FullDllName;
    /*0x02C*/     UNICODE_STRING32 BaseDllName;
    /*0x034*/     ULONG32 Flags;
    /*0x038*/     UINT16 LoadCount;
    /*0x03A*/     UINT16 TlsIndex;
    union
    {
        LIST_ENTRY32 HashLinks;
        struct
        {
            ULONG32 SectionPointer;
            ULONG32 CheckSum;
        };
    };
    union
    {
        ULONG32 TimeDateStamp;
        ULONG32 LoadedImports;
    };
    /*0x048*/     ULONG32 EntryPointActivationContext;
    /*0x04C*/     ULONG32        PatchInformation;
    /*0x050*/     LIST_ENTRY32 ForwarderLinks;                       // 2 elements, 0x8 bytes (sizeof)
    /*0x058*/     LIST_ENTRY32 ServiceTagLinks;                      // 2 elements, 0x8 bytes (sizeof)
    /*0x060*/     LIST_ENTRY32 StaticLinks;                          // 2 elements, 0x8 bytes (sizeof)
    /*0x068*/     ULONG32        ContextInformation;
    /*0x06C*/     ULONG32      OriginalBase;
    /*0x070*/     LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

#endif