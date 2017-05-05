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

    - Registry.h

Abstract:

    - 

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef __REGISTRY_H__
#define __REGISTRY_H__

#define HCELL_TYPE_MASK 0x80000000
#define HCELL_TYPE_SHIFT 31

#define HCELL_TABLE_MASK 0x7fe00000
#define HCELL_TABLE_SHIFT 21

#define HCELL_BLOCK_MASK 0x001ff000
#define HCELL_BLOCK_SHIFT 12

#define HCELL_OFFSET_MASK 0x00000fff

#define CM_FAST_LEAF_SIGNATURE 'fl'
#define CM_HASH_LEAF_SIGNATURE 'hl'
#define CM_INDEX_ROOT_SIGNATURE 'ir'
#define CM_INDEX_LEAF_SIGNATURE 'il'

#define CM_KEY_NODE_SIGNATURE 'kn'
#define CM_LINK_NODE_SIGNATURE 'kl'
#define CM_KEY_VALUE_SIGNATURE 'kv'

#define CM_FLAG_UNTRUSTED 0x1

#define CM_HIVE_SIGNATURE 0xbee0bee0

#define MAX_VALUE_NAME 16383

typedef struct _CM_INDEX {
    ULONG CellIndex;
    CHAR NameHint[4];
} CM_INDEX, *PCM_INDEX;

typedef struct _CM_KEY_FAST_INDEX {
    USHORT Signature;
    USHORT Count;
    CM_INDEX Index[1];
} CM_KEY_FAST_INDEX, *PCM_KEY_FAST_INDEX;

typedef struct _CM_KEY_INDEX {
    USHORT Signature;
    USHORT Count;
    ULONG CellIndex[1];
} CM_KEY_INDEX, *PCM_KEY_INDEX;

typedef struct _HIVE_OBJECT {
    ULONG64 HivePtr;
    ULONG64 KeyNodePtr;

    ULONG Flags;

    WCHAR FileUserName[MAX_PATH];
    WCHAR HiveRootPath[MAX_PATH];

    ULONG64 GetCellRoutine;
    ULONG64 ReleaseCellRoutine;
    ULONG64 Allocate;
    ULONG64 Free;
    ULONG64 FileSetSize;
    ULONG64 FileWrite;
    ULONG64 FileRead;
    ULONG64 FileFlush;
} HIVE_OBJECT, *PHIVE_OBJECT;

typedef struct _KEY_NAME {
    WCHAR Name[MAX_PATH];
} KEY_NAME, *PKEY_NAME ;

typedef struct _KEY_NODE {
    WCHAR Name[MAX_PATH];
    ExtRemoteTyped KeyNode;
} KEY_NODE, *PKEY_NODE;


ULONG64
RegGetCellPaged(
    ExtRemoteTyped KeyHive,
    ULONG CellIndex
);

VOID
RegReadKeyNode(
    ExtRemoteTyped KeyHive,
    ExtRemoteTyped KeyNode
);

VOID
RegReadKeyValue(
    ExtRemoteTyped KeyHive,
    ExtRemoteTyped KeyValue
);

LPWSTR
RegGetKeyName(
    ExtRemoteTyped KeyControlBlock
);

BOOL
RegGetKeyValue(
    _In_ PWSTR FullKeyPath,
    _In_ PWSTR ValueName,
    _In_ PVOID Data,
    _In_ ULONG DataLength
    );

vector<KEY_NAME>
RegGetKeyValuesNames(
    _In_ PWSTR FullKeyPath
    );

vector<KEY_NODE>
RegGetSubKeys(
    _In_ PWSTR FullKeyPath
    );

BOOL
RegInitialize(
    VOID
    );

vector<HIVE_OBJECT>
GetHives(
);
#endif