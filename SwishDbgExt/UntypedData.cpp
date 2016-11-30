/*++
    MoonSols Incident Response & Digital Forensics Debugging Extension

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

    - UntypedData.h

Abstract:

- http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx
    - TODO: set symbols noisy

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "SwishDbgExt.h"

#define InitField(a, b, c) {a, b, c}
#define InitPlatform(Platform, Minor, Major, d, Size, Type) {Platform, Minor, Major, d, Size, (ExtRemoteUnTyped::TYPED_DATA_FIELD *)Type}
#define InitType(TypeName, Type) {TypeName, (ExtRemoteUnTyped::TYPED_DATA_VERSION *)Type}

ExtRemoteUnTyped::TYPED_DATA_FIELD Nt_Smc_Cache_Ref_AMD64_7600[] = {
    // SMC_CACHE_REF
    InitField("Cache", 0x0, sizeof(ULONG64)), // Ptr SMC_CACHE
    InitField("RefCount", 0x8, sizeof(ULONG64)),
    InitField("AddRemoveLock", 0x10, sizeof(ULONG64)),
    InitField("SeqNumber", 0x18, sizeof(ULONG)),

    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Nt_Sm_AMD64_7600[] = {
    // SMC_CACHE
    InitField("CacheId", 0x0, sizeof(ULONG32)),
    InitField("DeviceSectorSize", 0x4, sizeof(ULONG32)),
    InitField("RegionCount", 0x8, sizeof(ULONG32)),
    // SMC_CACHE.PARAMETERS
    InitField("CacheParams.CacheFileSize", 0x10, sizeof(ULONG64)),
    // SMC_CACHE.FILE_INFO
    InitField("FileInfo.FileHandle", 0x28 + 0x0, sizeof(ULONG64)), // Ptr
    InitField("FileInfo.FileObject", 0x28 + 0x8, sizeof(ULONG64)), // Ptr32 _FILE_OBJECT
    InitField("FileInfo.VolumeFileObject", 0x28 + 0x10, sizeof(ULONG64)), // Ptr32 _FILE_OBJECT
    InitField("FileInfo.VolumeDeviceObject", 0x28 + 0x18, sizeof(ULONG64)), // Ptr32 _DEVICE_OBJECT
    InitField("FileInfo.VolumePnpHandle", 0x28 + 0x20, sizeof(ULONG64)), // Ptr32 
    InitField("FileInfo.UsageNotificationIrp", 0x28 + 0x28, sizeof(ULONG64)), // Ptr32 _IRP
    InitField("UniqueId", 0x1a8, sizeof(WCHAR)* 256),

    // SM_GLOBALS
    /*
    .text:000000014019DA0D                 lea     rcx, [rdi+880h]
    .text:000000014019DA26                 call    SmLogRetrieve
    */
    InitField("StoreMgr.Log", 0x880, 0x58),
    InitField("CacheMgr", 0x9a0, 0x118),

    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Nt_Smc_Cache_Ref_I386_7600[] = {
    // SMC_CACHE_REF
    InitField("Cache", 0x0, sizeof(ULONG32)),
    InitField("RefCount", 0x4, sizeof(ULONG32)),
    InitField("AddRemoveLock", 0x8, sizeof(ULONG32)),
    InitField("SeqNumber", 0xC, sizeof(ULONG)),
    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Nt_Sm_I386_7600[] = {
    // SMC_CACHE
    InitField("CacheId", 0x0, sizeof(ULONG32)),
    InitField("DeviceSectorSize", 0x4, sizeof(ULONG32)),
    InitField("RegionCount", 0x8, sizeof(ULONG32)),
    // SMC_CACHE.PARAMETERS
    InitField("CacheParams.CacheFileSize", 0x10, sizeof(ULONG64)),
    // SMC_CACHE.FILE_INFO
    InitField("FileInfo.FileHandle", 0x28 + 0x0, sizeof(ULONG32)), // Ptr
    InitField("FileInfo.FileObject", 0x28 + 0x4, sizeof(ULONG32)), // Ptr32 _FILE_OBJECT
    InitField("FileInfo.VolumeFileObject", 0x28 + 0x8, sizeof(ULONG32)), // Ptr32 _FILE_OBJECT
    InitField("FileInfo.VolumeDeviceObject", 0x28 + 0xc, sizeof(ULONG32)), // Ptr32 _DEVICE_OBJECT
    InitField("FileInfo.VolumePnpHandle", 0x28 + 0x10, sizeof(ULONG32)), // Ptr32 
    InitField("FileInfo.UsageNotificationIrp", 0x28 + 0x14, sizeof(ULONG32)), // Ptr32 _IRP
    InitField("UniqueId", 0x17c, sizeof(WCHAR) * 256),

    // SM_GLOBALS
    InitField("StoreMgr.Log", 0x510, 0x58), // _SM_LOG_CTX
    InitField("CacheMgr", 0x5b4, 0x118), // _SMC_CACHE_MANAGER

    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_VERSION Nt_Sm[] = {
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 7600, 15, 0, 0x1c, &Nt_Sm_AMD64_7600),
    InitPlatform(IMAGE_FILE_MACHINE_I386, 7600, 15, 0, 0x10, &Nt_Sm_I386_7600),
    InitPlatform(0, 0, 0, 0, 0, NULL)
};

ExtRemoteUnTyped::TYPED_DATA_VERSION Nt_Smc_Cache_ref[] = {
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 7600, 15, 0, 0x1c, &Nt_Smc_Cache_Ref_AMD64_7600),
    InitPlatform(IMAGE_FILE_MACHINE_I386, 7600, 15, 0, 0x10, &Nt_Smc_Cache_Ref_I386_7600),
    InitPlatform(0, 0, 0, 0, 0, NULL)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD TcpIp_ParitionTable_AMD64_7600[] = {
    InitField("HashTables", 0x8, sizeof(ULONG64)),
    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD TcpIp_ParitionTable_I386_7600[] = {
    InitField("HashTables", 0x4, sizeof(ULONG32)),
    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_VERSION TcpIp_PartitionTable[] = {
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 7600, 15, 0, 0x78, &TcpIp_ParitionTable_AMD64_7600),
    InitPlatform(IMAGE_FILE_MACHINE_I386, 7600, 15, 0, 0x48, &TcpIp_ParitionTable_I386_7600),
    InitPlatform(0, 0, 0, 0, 0, NULL)
};

// We group all the structures in one variable.
ExtRemoteUnTyped::TYPED_DATA_FIELD TcpIp_Tcb_AMD64_7600[] = {
    // TCB
    InitField("Client", 0x010, sizeof(ULONG64)), // Ptr64 _TCP_CLIENT
    InitField("Path", 0x20, sizeof(ULONG64)),
    InitField("HashTableEntry", 0x28, 0x18), // RTL_DYNAMIC_HASH_TABLE_ENTRY
    InitField("State", 0x68, sizeof(ULONG)),
    InitField("LocalPort", 0x6c, sizeof(USHORT)),
    InitField("RemotePort", 0x6e, sizeof(USHORT)),
    InitField("OwningProcess", 0x238, sizeof(ULONG64)), // Ptr64 _EPROCESS

    // NL_PATH
    InitField("SourceAddress", 0x00, sizeof(ULONG64)), // Ptr64 _NL_LOCAL_ADDRESS
    InitField("DestinationAddress", 0x10, sizeof(ULONG64)), // Ptr64 UChar

    // _NL_LOCAL_ADDRESS
    InitField("Identifier", 0x10, sizeof(ULONG64)), // _NL_ADDRESS_IDENTIFIER
    
    // _NL_ADDRESS_IDENTIFIER
    InitField("Address", 0x00, sizeof(ULONG64)), // Ptr64 UChar

    //tcpip!_TCP_CLIENT
    InitField("Family", 0x014, sizeof(USHORT)),
    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD TcpIp_Tcb_I386_7600[] = {
    // TCB
    InitField("Client", 0x008, sizeof(ULONG64)), // Ptr64 _TCP_CLIENT
    InitField("Path", 0x010, sizeof(ULONG32)),
    InitField("HashTableEntry", 0x014, 0xc), // RTL_DYNAMIC_HASH_TABLE_ENTRY
    InitField("State", 0x034, sizeof(ULONG)),
    InitField("LocalPort", 0x038, sizeof(USHORT)),
    InitField("RemotePort", 0x03a, sizeof(USHORT)),
    InitField("OwningProcess", 0x174, sizeof(ULONG32)), // Ptr64 _EPROCESS

    // NL_PATH
    InitField("SourceAddress", 0x00, sizeof(ULONG32)), // Ptr64 _NL_LOCAL_ADDRESS
    InitField("DestinationAddress", 0x08, sizeof(ULONG32)), // Ptr64 UChar

    // _NL_LOCAL_ADDRESS
    InitField("Identifier", 0x00c, sizeof(ULONG32)), // _NL_ADDRESS_IDENTIFIER

    // _NL_ADDRESS_IDENTIFIER
    InitField("Address", 0x00, sizeof(ULONG32)), // Ptr64 UChar

    // _TCP_CLIENT
    InitField("Family", 0x00c, sizeof(USHORT)),

    InitField(NULL, 0, 0)
};


// We group all the structures in one variable.
ExtRemoteUnTyped::TYPED_DATA_FIELD TcpIp_Tcb_AMD64_6000[] = {
    // TCB
    InitField("Client", 0x010, sizeof(ULONG64)), // Ptr64 _TCP_CLIENT
    InitField("Path", 0x20, sizeof(ULONG64)),
    InitField("HashTableEntry", 0x28, 0x18), // RTL_DYNAMIC_HASH_TABLE_ENTRY
    InitField("State", 0x50, sizeof(ULONG)),
    InitField("LocalPort", 0x54, sizeof(USHORT)),
    InitField("RemotePort", 0x56, sizeof(USHORT)),
    InitField("OwningProcess", 0x208, sizeof(ULONG64)), // Ptr64 _EPROCESS

    // NL_PATH
    InitField("SourceAddress", 0x00, sizeof(ULONG64)), // Ptr64 _NL_LOCAL_ADDRESS
    InitField("DestinationAddress", 0x10, sizeof(ULONG64)), // Ptr64 UChar

    // _NL_LOCAL_ADDRESS
    InitField("Identifier", 0x10, sizeof(ULONG64)), // _NL_ADDRESS_IDENTIFIER

    // _NL_ADDRESS_IDENTIFIER
    InitField("Address", 0x00, sizeof(ULONG64)), // Ptr64 UChar

    //tcpip!_TCP_CLIENT
    InitField("Family", 0x014, sizeof(USHORT)),
    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD TcpIp_Tcb_I386_6000[] = {
    // TCB
    InitField("Client", 0x008, sizeof(ULONG64)), // Ptr64 _TCP_CLIENT
    InitField("Path", 0x010, sizeof(ULONG32)),
    InitField("HashTableEntry", 0x014, 0xc), // RTL_DYNAMIC_HASH_TABLE_ENTRY
    InitField("State", 0x028, sizeof(ULONG)),
    InitField("LocalPort", 0x02c, sizeof(USHORT)),
    InitField("RemotePort", 0x02e, sizeof(USHORT)),
    InitField("OwningProcess", 0x160, sizeof(ULONG32)), // Ptr64 _EPROCESS

    // NL_PATH
    InitField("SourceAddress", 0x00, sizeof(ULONG32)), // Ptr64 _NL_LOCAL_ADDRESS
    InitField("DestinationAddress", 0x08, sizeof(ULONG32)), // Ptr64 UChar

    // _NL_LOCAL_ADDRESS
    InitField("Identifier", 0x00c, sizeof(ULONG32)), // _NL_ADDRESS_IDENTIFIER

    // _NL_ADDRESS_IDENTIFIER
    InitField("Address", 0x00, sizeof(ULONG32)), // Ptr64 UChar

    //tcpip!_TCP_CLIENT
    InitField("Family", 0x00c, sizeof(USHORT)),

    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_VERSION TcpIp_Tcb[] = {
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 7600, 15, 0, 0x310, &TcpIp_Tcb_AMD64_7600),
    InitPlatform(IMAGE_FILE_MACHINE_I386, 7600, 15, 0, 0x208, &TcpIp_Tcb_I386_7600),
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 6000, 5, 0, 0x310, &TcpIp_Tcb_AMD64_6000),
    InitPlatform(IMAGE_FILE_MACHINE_I386, 6000, 5, 0, 0x208, &TcpIp_Tcb_I386_6000),
    InitPlatform(0, 0, 0, 0, 0, NULL)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Conhost_ConsoleInformation_AMD64_7600[] = {
    // _CONSOLE_INFORMATION
    InitField("ProcessList", 0x28, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("CurrentScreenBuffer", 0xE0, sizeof(ULONG64)), // Ptr _SCREEN_INFORMATION
    InitField("ScreenBuffer", 0xE8, sizeof(ULONG64)), // Ptr _SCREEN_INFORMATION
    InitField("HistoryList", 0x148, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("ExeAliasList", 0x158, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("HistoryBufferCount", 0x168, sizeof(USHORT)),
    InitField("HistoryBufferMax", 0x16A, sizeof(USHORT)),
    InitField("CommandHistorySize", 0x16C, sizeof(USHORT)),
    InitField("OriginalTitle", 0x170, sizeof(ULONG64)), // Ptr String[256]
    InitField("Title", 0x178, sizeof(ULONG64)), // Ptr String[256]

    // _COMMAND_HISTORY
    InitField("ListEntry", 0x00, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("Flags", 0x10, sizeof(ULONG)), // ('Allocated'=0, 'Reset' = 1)
    InitField("Application", 0x18, sizeof(ULONG64)), // Ptr String[256]
    InitField("CommandCount", 0x20, sizeof(USHORT)),
    InitField("LastAdded", 0x22, sizeof(USHORT)),
    InitField("LastDisplayed", 0x24, sizeof(USHORT)),
    InitField("FirstCommand", 0x26, sizeof(USHORT)),
    InitField("CommandCountMax", 0x28, sizeof(USHORT)),
    InitField("ProcessHandle", 0x30, sizeof(ULONG64)), // -HANDLE
    InitField("PopupList", 0x38, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("CommandBucket", 0x48, sizeof(ULONG64)), // ptr _COMMAND[CommandCount]

    // _COMMAND
    InitField("CmdLength", 0x0, sizeof(USHORT)),
    InitField("Cmd", 0x2, sizeof(UCHAR)),

    // _SCREEN_INFORMATION
    InitField("ScreenX", 0x8, sizeof(USHORT)),
    InitField("ScreenY", 0xA, sizeof(USHORT)),
    InitField("Rows", 0x48, sizeof(ULONG64)), // Ptr _ROW
    InitField("Next", 0x128, sizeof(ULONG64)), // Ptr _SCREEN_INFORMATION

    // _ROW
    InitField("Chars", 0x8, sizeof(ULONG64)), // Ptr String[256]

    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Conhost_ConsoleInformation_I386_7600[] = {
    // _CONSOLE_INFORMATION
    InitField("ProcessList", 0x18, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("CurrentScreenBuffer", 0x98, sizeof(ULONG32)), // Ptr _SCREEN_INFORMATION
    InitField("ScreenBuffer", 0x9c, sizeof(ULONG32)), // Ptr _SCREEN_INFORMATION
    InitField("HistoryList", 0xd4, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("ExeAliasList", 0xdc, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("HistoryBufferCount", 0xe4, sizeof(USHORT)),
    InitField("HistoryBufferMax", 0xe6, sizeof(USHORT)),
    InitField("CommandHistorySize", 0xe8, sizeof(USHORT)),
    InitField("OriginalTitle", 0xec, sizeof(ULONG32)), // Ptr String[256]
    InitField("Title", 0xf0, sizeof(ULONG32)), // Ptr String[256]

    // _COMMAND_HISTORY
    InitField("ListEntry", 0x00, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("Flags", 0x8, sizeof(ULONG)), // ('Allocated'=0, 'Reset' = 1)
    InitField("Application", 0xc, sizeof(ULONG32)), // Ptr String[256]
    InitField("CommandCount", 0x10, sizeof(USHORT)),
    InitField("LastAdded", 0x12, sizeof(USHORT)),
    InitField("LastDisplayed", 0x14, sizeof(USHORT)),
    InitField("FirstCommand", 0x16, sizeof(USHORT)),
    InitField("CommandCountMax", 0x18, sizeof(USHORT)),
    InitField("ProcessHandle", 0x1c, sizeof(ULONG32)), // -HANDLE
    InitField("PopupList", 0x20, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("CommandBucket", 0x28, sizeof(ULONG32)), // ptr _COMMAND[CommandCount]

    // _COMMAND
    InitField("CmdLength", 0x0, sizeof(USHORT)),
    InitField("Cmd", 0x2, sizeof(UCHAR)),

    // _SCREEN_INFORMATION
    InitField("ScreenX", 0x8, sizeof(USHORT)),
    InitField("ScreenY", 0xA, sizeof(USHORT)),
    InitField("Rows", 0x3c, sizeof(ULONG32)), // Ptr _ROW
    InitField("Next", 0xdc, sizeof(ULONG32)), // Ptr _SCREEN_INFORMATION

    // _ROW
    InitField("Chars", 0x8, sizeof(ULONG32)), // Ptr String[256]

    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Conhost_ConsoleInformation_I386_2600[] = {
    // _CONSOLE_INFORMATION
    InitField("ProcessList", 0x100, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("CurrentScreenBuffer", 0xb0, sizeof(ULONG32)), // Ptr _SCREEN_INFORMATION
    InitField("ScreenBuffer", 0xb4, sizeof(ULONG32)), // Ptr _SCREEN_INFORMATION
    InitField("HistoryList", 0x108, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("ExeAliasList", 0x110, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("HistoryBufferCount", 0x118, sizeof(USHORT)),
    InitField("HistoryBufferMax", 0x11a, sizeof(USHORT)),
    InitField("CommandHistorySize", 0x11c, sizeof(USHORT)),
    InitField("OriginalTitle", 0x124, sizeof(ULONG32)), // Ptr String[256]
    InitField("Title", 0x128, sizeof(ULONG32)), // Ptr String[256]

    // _COMMAND_HISTORY
    InitField("ListEntry", 0x04, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("Flags", 0x0, sizeof(ULONG)), // ('Allocated'=0, 'Reset' = 1)
    InitField("Application", 0xc, sizeof(ULONG32)), // Ptr String[256]
    InitField("CommandCount", 0x10, sizeof(USHORT)),
    InitField("LastAdded", 0x12, sizeof(USHORT)),
    InitField("LastDisplayed", 0x14, sizeof(USHORT)),
    InitField("FirstCommand", 0x16, sizeof(USHORT)),
    InitField("CommandCountMax", 0x18, sizeof(USHORT)),
    InitField("ProcessHandle", 0x1c, sizeof(ULONG32)), // -HANDLE
    InitField("PopupList", 0x20, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("CommandBucket", 0x28, sizeof(ULONG32)), // ptr _COMMAND[CommandCount]

    // _COMMAND
    InitField("CmdLength", 0x0, sizeof(USHORT)),
    InitField("Cmd", 0x2, sizeof(UCHAR)),

    // _SCREEN_INFORMATION
    InitField("ScreenX", 0x24, sizeof(USHORT)),
    InitField("ScreenY", 0x26, sizeof(USHORT)),
    InitField("Rows", 0x58, sizeof(ULONG32)), // Ptr _ROW
    InitField("Next", 0xf8, sizeof(ULONG32)), // Ptr _SCREEN_INFORMATION

    // _ROW
    InitField("Chars", 0x8, sizeof(ULONG32)), // Ptr String[256]

    InitField(NULL, 0, 0)
};


ExtRemoteUnTyped::TYPED_DATA_FIELD Conhost_ConsoleInformation_AMD64_2600[] = {
    // _CONSOLE_INFORMATION
    InitField("CurrentScreenBuffer", 0xe8, sizeof(ULONG64)), // Ptr _SCREEN_INFORMATION
    InitField("ScreenBuffer", 0xf0, sizeof(ULONG64)), // Ptr _SCREEN_INFORMATION
    InitField("ProcessList", 0x178, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("HistoryList", 0x188, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("ExeAliasList", 0x198, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("HistoryBufferCount", 0x1a8, sizeof(USHORT)),
    InitField("HistoryBufferMax", 0x1aa, sizeof(USHORT)),
    InitField("CommandHistorySize", 0x1ac, sizeof(USHORT)),
    InitField("OriginalTitle", 0x1b0, sizeof(ULONG64)), // Ptr String[256]
    InitField("Title", 0x1b8, sizeof(ULONG64)), // Ptr String[256]

    // _COMMAND_HISTORY
    InitField("Flags", 0x0, sizeof(ULONG)), // ('Allocated'=0, 'Reset' = 1)
    InitField("ListEntry", 0x08, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("Application", 0x18, sizeof(ULONG64)), // Ptr String[256]
    InitField("CommandCount", 0x20, sizeof(USHORT)),
    InitField("LastAdded", 0x22, sizeof(USHORT)),
    InitField("LastDisplayed", 0x24, sizeof(USHORT)),
    InitField("FirstCommand", 0x26, sizeof(USHORT)),
    InitField("CommandCountMax", 0x28, sizeof(USHORT)),
    InitField("ProcessHandle", 0x30, sizeof(ULONG64)), // -HANDLE
    InitField("PopupList", 0x38, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("CommandBucket", 0x48, sizeof(ULONG64)), // ptr _COMMAND[CommandCount]

    // _COMMAND
    InitField("CmdLength", 0x0, sizeof(USHORT)),
    InitField("Cmd", 0x2, sizeof(UCHAR)),

    // _SCREEN_INFORMATION
    InitField("ScreenX", 0x28, sizeof(USHORT)),
    InitField("ScreenY", 0x2A, sizeof(USHORT)),
    InitField("Rows", 0x68, sizeof(ULONG64)), // Ptr _ROW
    InitField("Next", 0x128, sizeof(ULONG64)), // Ptr _SCREEN_INFORMATION

    // _ROW
    InitField("Chars", 0x8, sizeof(ULONG64)), // Ptr String[256]

    InitField(NULL, 0, 0)
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Nt_Misc_I386_2600[] = {
    // KTIMER_TABLE_ENTRY
    InitField("Entry.Flink", 0x0, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("Entry.Blink", 0x4, sizeof(ULONG32)), // _LIST_ENTRY
    InitField("Time", 0x8, sizeof(ULONG64)), // _ULARGE_INTEGER
};

ExtRemoteUnTyped::TYPED_DATA_FIELD Nt_Misc_AMD64_2600[] = {
    // KTIMER_TABLE_ENTRY
    InitField("Entry.Flink", 0x0, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("Entry.Blink", 0x8, sizeof(ULONG64)), // _LIST_ENTRY
    InitField("Time", 0x8, sizeof(ULONG64)), // _ULARGE_INTEGER
};

ExtRemoteUnTyped::TYPED_DATA_VERSION Conhost_ConsoleInformation[] = {
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 7600, 15, 0, 0x400 /* Unknown */, &Conhost_ConsoleInformation_AMD64_7600),
    InitPlatform(IMAGE_FILE_MACHINE_I386, 7600, 15, 0, 0x400 /* Unknonw */, &Conhost_ConsoleInformation_I386_7600),
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 2600, 15, 0, 0x400 /* Unknown */, &Conhost_ConsoleInformation_AMD64_2600),
    InitPlatform(IMAGE_FILE_MACHINE_I386, 2600, 15, 0, 0x400 /* Unknonw */, &Conhost_ConsoleInformation_I386_2600),

    InitPlatform(0, 0, 0, 0, 0, NULL)
};

ExtRemoteUnTyped::TYPED_DATA_VERSION Nt_Misc[] = {
    InitPlatform(IMAGE_FILE_MACHINE_I386, 2600, 15, 0, 0x10, &Nt_Misc_I386_2600),
    InitPlatform(IMAGE_FILE_MACHINE_AMD64, 2600, 15, 0, 0x18, &Nt_Misc_AMD64_2600),

    InitPlatform(0, 0, 0, 0, 0, NULL)
};

ExtRemoteUnTyped::TYPED_DATA g_UntypedData[] = {
    InitType("tcpip!_PARTITION_TABLE", &TcpIp_PartitionTable),
    InitType("tcpip!_TCB", &TcpIp_Tcb),
    InitType("conhost!_CONSOLE_INFORMATION", &Conhost_ConsoleInformation),
    InitType("nt!_KTIMER_TABLE_ENTRY", &Nt_Misc),
    InitType("nt!_SMC_CACHE_REF", &Nt_Smc_Cache_ref),
    InitType("nt!_SMC_CACHE", &Nt_Sm),
    InitType("nt!_SM_GLOBALS", &Nt_Sm),
    InitType(NULL, NULL)
};

VOID
ExtRemoteUnTyped::Set(
    _In_ ULONG64 Ptr,
    _In_ PCSTR TypeName
)
/*++

Routine Description:

    Description.

Arguments:

    Ptr - 
    TypeName -

Return Value:

    VOID.

--*/
{
    m_UntypedDataPtr = Ptr;

    RtlZeroMemory(m_TypeName, sizeof(m_TypeName));
    RtlZeroMemory(m_Field, sizeof(m_Field));

    strcpy_s(m_TypeName, sizeof(m_TypeName), TypeName);

    PTYPED_DATA_VERSION ReturnType = NULL;

    for (UINT i = 0; g_UntypedData[i].TypeName; i += 1)
    {
        if (_stricmp(g_UntypedData[i].TypeName, m_TypeName) == 0)
        {
            for (UINT j = 0; g_UntypedData[i].Type[j].MachineType; j += 1)
            {
                if ((g_UntypedData[i].Type[j].MachineType == g_Ext->m_Machine) &&
                    (g_Ext->m_Minor >= g_UntypedData[i].Type[j].MinorVersion))
                {
                    if ((ReturnType && (ReturnType->MinorVersion < g_UntypedData[i].Type[j].MinorVersion)) || !ReturnType)
                    {
                        ReturnType = &g_UntypedData[i].Type[j];
                    }
                }
            }

            break;
        }
    }

    if (ReturnType)
    {
        m_TypedData = ReturnType;
        m_Initialized = TRUE;
    }
}

ULONG
GetUntypedTypeSize(
    _In_ PCSTR TypeName
)
/*++

Routine Description:

    Description.

Arguments:

    TypeName -

Return Value:

    ULONG.

--*/
{
    ExtRemoteUnTyped Tmp(0, TypeName);

    return Tmp.m_TypedData->TypeSize;
}

ExtRemoteUnTyped::PTYPED_DATA_FIELD
ExtRemoteUnTyped::GetField(
    _In_ PCSTR Field
)
/*++

Routine Description:

    Description.

Arguments:

    Field -

Return Value:

    PTYPED_DATA_FIELD.

--*/
{
    PTYPED_DATA_FIELD ReturnResult = NULL;
    if (!m_Initialized) return FALSE;

    for (UINT i = 0; m_TypedData->Fields[i].FieldName; i += 1)
    {
        if (_stricmp(m_TypedData->Fields[i].FieldName, Field) == 0)
        {
            ReturnResult = &m_TypedData->Fields[i];
            goto CleanUp;
        }
    }

CleanUp:
    return ReturnResult;
}

ULONG
GetFieldOffset(
    _In_ PCSTR TypeName,
    _In_ PCSTR Field
)
/*++

Routine Description:

    Description.

Arguments:

    TypeName -
    Field -

Return Value:

    ULONG.

--*/
{
    ExtRemoteUnTyped Tmp(TypeName);

    return Tmp.GetFieldOffset(Field);
}

BOOLEAN
ExtRemoteUnTyped::HasField(
    _In_ PCSTR Field
)
/*++

Routine Description:

    Description.

Arguments:

    Field -

Return Value:

    BOOLEAN.

--*/
{
    if (!m_Initialized) return FALSE;

    BOOLEAN Result = FALSE;

    if (GetField(Field)) Result = TRUE;

    return Result;
}

ULONG
ExtRemoteUnTyped::GetFieldOffset(
    _In_ PCSTR Field
)
/*++

Routine Description:

    Description.

Arguments:

    Field -

Return Value:

    ULONG.

--*/
{
    ULONG Offset = 0;

    PTYPED_DATA_FIELD TypedField = GetField(Field);
    if (TypedField) Offset = TypedField->Offset;

    return Offset;
}

VOID
ExtRemoteUnTyped::SubtractOffset(
    _In_ PCSTR Field
)
/*++

Routine Description:

    Description.

Arguments:

    Field -

Return Value:

    VOID.

--*/
{
    ULONG Offset = GetFieldOffset(Field);
    m_UntypedDataPtr -= Offset;

    ExtRemoteData::Clear();
    ExtRemoteData::Set(m_UntypedDataPtr, m_TypedData->TypeSize);
}

ULONG64
ExtRemoteUnTyped::GetPointerTo(
    VOID
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    ULONG64.

--*/
{
    return m_UntypedDataPtr;
}

ExtRemoteUnTyped
ExtRemoteUnTyped::Field(
    _In_ PCSTR Field,
    _In_ BOOLEAN IsPtr
)
/*++

Routine Description:

    Description.

Arguments:

    Field -
    IsPtr - 

Return Value:

    ExtRemoteUntyped.

--*/
{
    PTYPED_DATA_FIELD TypedField = GetField(Field);

    ULONG64 Ptr = m_UntypedDataPtr + TypedField->Offset;

    if (IsPtr) ReadPointer(Ptr, &Ptr);

    return ExtRemoteUnTyped(Ptr,
                            m_TypeName,
                            m_Field, // Field
                            TypedField->Size);
}

ExtRemoteUnTyped
ExtRemoteUnTyped::Field(
    _In_ PCSTR Field
)
/*++

Routine Description:

    Description.

Arguments:

    Field - 

Return Value:

    ExtRemoteUnTyped.

--*/
{
    PTYPED_DATA_FIELD TypedField = GetField(Field);

    // g_Ext->Dml("m_TypeName = \"%s\", Offset = 0x%I64X m_Field = \"%s\" or \"%s\", Size = 0x%x\n",
    //    m_TypeName, m_UntypedDataPtr + TypedField->Offset, m_Field, Field, TypedField->Size);

    return ExtRemoteUnTyped(m_UntypedDataPtr + TypedField->Offset,
                            m_TypeName,
                            m_Field, // Field
                            TypedField->Size);
}

ExtRemoteUnTyped
ExtRemoteUnTyped::ArrayElement(
    _In_ LONG64 Index
)
/*++

Routine Description:

    Description.

Arguments:

    Index -

Return Value:

    ExtRemoteUnTyped.

--*/
{
    ULONG ArrayOffset;

    if (m_FieldSize) ArrayOffset = m_FieldSize * (ULONG)Index;
    else ArrayOffset = m_TypedData->TypeSize * (ULONG)Index;
    return ExtRemoteUnTyped(m_UntypedDataPtr + ArrayOffset, m_TypeName);
}
