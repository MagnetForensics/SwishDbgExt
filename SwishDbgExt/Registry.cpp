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

    - Registry.cpp

Abstract:

    - 

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"


vector<HIVE_OBJECT> g_Hives;


vector<KEY_NAME>
GetKeysNames(
    _In_ PWSTR FullKeyPath
    )
{
    vector<KEY_NAME> SubKeysNames;
    KEY_NAME KeyName;
    PWSTR CurrentName;
    PWSTR RemainingName;
    ULONG Length;

    CurrentName = FullKeyPath;
    RemainingName = FullKeyPath;

    while (*CurrentName) {

        CurrentName++;
        RemainingName++;

        while (*RemainingName && (*RemainingName != L'\\')) {

            RemainingName++;
        }

        Length = (ULONG)(RemainingName - CurrentName);

        if (Length) {

            StringCchCopyNW(KeyName.Name, _countof(KeyName.Name), CurrentName, Length);

            SubKeysNames.push_back(KeyName);
        }

        CurrentName = RemainingName;
    }

    return SubKeysNames;
}

vector<KEY_NODE>
GetSubKeys(
    _In_ ExtRemoteTyped KeyHive,
    _In_ ExtRemoteTyped KeyNode
    )
{
    vector<KEY_NODE> SubKeys;

    ULONG SubKeysStableCount = KeyNode.Field("SubKeyCounts").ArrayElement(0).GetUlong();
    ULONG SubKeysVolatileCount = KeyNode.Field("SubKeyCounts").ArrayElement(1).GetUlong();

    if (SubKeysStableCount) {

        ULONG SubKeysStableIndex = KeyNode.Field("SubKeyLists").ArrayElement(0).GetUlong();
        ULONG64 SubKeysStableTableAddress = RegGetCellPaged(KeyHive, SubKeysStableIndex);

        ULONG MaxSize = sizeof(CM_KEY_FAST_INDEX) + SubKeysStableCount * sizeof(CM_INDEX);

        PULONG SubKeysStableTable = (PULONG)calloc(MaxSize, sizeof(BYTE));

        if (SubKeysStableTable) {

            if (ExtRemoteTypedEx::ReadVirtual(SubKeysStableTableAddress, SubKeysStableTable, MaxSize, NULL) == S_OK) {
                        
                PCM_KEY_INDEX CmKeyIndex = (PCM_KEY_INDEX)SubKeysStableTable;

                for (UINT i = 0; i < SubKeysStableCount; i++) {

                    try {

                        ULONG64 Address = 0;
                        KEY_NODE SubKey = {0};

                        if ((CmKeyIndex->Signature == CM_INDEX_ROOT_SIGNATURE) || (CmKeyIndex->Signature == CM_INDEX_LEAF_SIGNATURE)) {

                            Address = RegGetCellPaged(KeyHive, CmKeyIndex->CellIndex[i]);
                        }
                        else if ((CmKeyIndex->Signature == CM_FAST_LEAF_SIGNATURE) || (CmKeyIndex->Signature == CM_HASH_LEAF_SIGNATURE)) {

                            PCM_KEY_FAST_INDEX CmKeyFastIndex = (PCM_KEY_FAST_INDEX)CmKeyIndex;
                            Address = RegGetCellPaged(KeyHive, CmKeyFastIndex->Index[i].CellIndex);
                        }

                        ExtRemoteTyped ChildKeyNode("(nt!_CM_KEY_NODE *)@$extin", Address);

                        SubKey.KeyNode = ChildKeyNode;

                        USHORT NameLength = ChildKeyNode.Field("NameLength").GetUshort();

                        if (NameLength) {

                            CHAR Name[MAX_PATH] = {0};

                            Address = ChildKeyNode.Field("Name").GetPointerTo().GetPtr();

                            ExtRemoteTypedEx::ReadVirtual(Address, Name, min(NameLength, sizeof(Name) - 1), NULL);

                            StringCchPrintfW(SubKey.Name, _countof(SubKey.Name), L"%S", Name);

                            SubKeys.push_back(SubKey);
                        }
                    }
                    catch (...) {

                    }
                }
            }

            free(SubKeysStableTable);
        }
    }

    if (SubKeysVolatileCount) {

        ULONG SubKeysVolatileIndex = KeyNode.Field("SubKeyLists").ArrayElement(1).GetUlong();
        ULONG64 SubKeysVolatileTableAddress = RegGetCellPaged(KeyHive, SubKeysVolatileIndex);

        ULONG MaxSize = sizeof(CM_KEY_FAST_INDEX) + SubKeysVolatileCount * sizeof(CM_INDEX);

        PULONG SubKeysVolatileTable = (PULONG)calloc(MaxSize, sizeof(BYTE));

        if (SubKeysVolatileTable) {

            if (ExtRemoteTypedEx::ReadVirtual(SubKeysVolatileTableAddress, SubKeysVolatileTable, MaxSize, NULL) == S_OK) {

                PCM_KEY_INDEX CmKeyIndex = (PCM_KEY_INDEX)SubKeysVolatileTable;

                for (UINT i = 0; i < SubKeysVolatileCount; i++) {

                    try {

                        ULONG64 Address = 0;
                        KEY_NODE SubKey = {0};

                        if ((CmKeyIndex->Signature == CM_INDEX_ROOT_SIGNATURE) || (CmKeyIndex->Signature == CM_INDEX_LEAF_SIGNATURE)) {

                            Address = RegGetCellPaged(KeyHive, CmKeyIndex->CellIndex[i]);
                        }
                        else if ((CmKeyIndex->Signature == CM_FAST_LEAF_SIGNATURE) || (CmKeyIndex->Signature == CM_HASH_LEAF_SIGNATURE)) {

                            PCM_KEY_FAST_INDEX CmKeyFastIndex = (PCM_KEY_FAST_INDEX)CmKeyIndex;
                            Address = RegGetCellPaged(KeyHive, CmKeyFastIndex->Index[i].CellIndex);
                        }

                        ExtRemoteTyped ChildKeyNode("(nt!_CM_KEY_NODE *)@$extin", Address);

                        SubKey.KeyNode = ChildKeyNode;

                        USHORT NameLength = ChildKeyNode.Field("NameLength").GetUshort();

                        if (NameLength) {

                            CHAR Name[MAX_PATH] = {0};

                            Address = ChildKeyNode.Field("Name").GetPointerTo().GetPtr();

                            ExtRemoteTypedEx::ReadVirtual(Address, Name, min(NameLength, sizeof(Name) - 1), NULL);

                            StringCchPrintfW(SubKey.Name, _countof(SubKey.Name), L"%S", Name);

                            SubKeys.push_back(SubKey);
                        }
                    }
                    catch (...) {

                    }
                }
            }

            free(SubKeysVolatileTable);
        }
    }

    return SubKeys;
}

ExtRemoteTyped
GetKeyNode(
    _In_ PWSTR FullKeyPath
    )
{
    ULONG64 CmpMasterHive;
    ULONG64 CmpRegistryRootObject;
    ExtRemoteTyped KeyNode;

    try {

        ReadPointer(CmpMasterHiveAddress, &CmpMasterHive);
        ReadPointer(CmpRegistryRootObjectAddress, &CmpRegistryRootObject);

        ExtRemoteTyped KeyHive("(nt!_HHIVE *)@$extin", CmpMasterHive);
        ExtRemoteTyped KeyBody("(nt!_CM_KEY_BODY *)@$extin", CmpRegistryRootObject);
        ExtRemoteTyped KeyControlBlock("(nt!_CM_KEY_CONTROL_BLOCK *)@$extin", KeyBody.Field("KeyControlBlock").GetPtr());

        ULONG KeyCell = KeyControlBlock.Field("KeyCell").GetUlong();

        KeyNode = ExtRemoteTyped("(nt!_CM_KEY_NODE *)@$extin", RegGetCellPaged(KeyHive, KeyCell));

        vector<KEY_NAME> KeysNames = GetKeysNames(FullKeyPath);

        for (size_t i = 1; i < KeysNames.size(); i++) {

            BOOL IsFound = FALSE;

            vector<KEY_NODE> SubKeys = GetSubKeys(KeyHive, KeyNode);

            for (size_t j = 0; j < SubKeys.size(); j++) {

                if (0 == _wcsicmp(KeysNames[i].Name, SubKeys[j].Name)) {

                    KeyNode = SubKeys[j].KeyNode;

                    if (KeyNode.Field("Signature").GetUshort() == CM_LINK_NODE_SIGNATURE) {

                        KeyHive = ExtRemoteTyped("(nt!_HHIVE *)@$extin", KeyNode.Field("ChildHiveReference.KeyHive").GetPtr());
                        KeyCell = KeyNode.Field("ChildHiveReference.KeyCell").GetUlong();
                        KeyNode = ExtRemoteTyped("(nt!_CM_KEY_NODE *)@$extin", RegGetCellPaged(KeyHive, KeyCell));
                    }

                    IsFound = TRUE;
                    break;
                }
            }

            if (!IsFound) {

                KeyNode = ExtRemoteTyped("(nt!_CM_KEY_NODE *)@$extin", NULL);
                break;
            }
        }
    }
    catch (...) {

    }

    return KeyNode;
}

ExtRemoteTyped
GetHive(
    _In_ PWSTR FullKeyPath
    )
{
    PHIVE_OBJECT Hive = NULL;
    ULONG64 HiveAddress = NULL;
    ULONG HiveRootLength;
    ULONG KeyPathLength;

    if (g_Hives.size()) {

        KeyPathLength = (ULONG)wcslen(FullKeyPath);

        for (size_t i = 0; i < g_Hives.size(); i++) {

            HiveRootLength = (ULONG)wcslen(g_Hives[i].HiveRootPath);

            if (HiveRootLength && (HiveRootLength <= KeyPathLength) && (0 == _wcsnicmp(g_Hives[i].HiveRootPath, FullKeyPath, HiveRootLength))) {

                Hive = &g_Hives[i];
                break;
            }
        }

        if (!Hive) {

            Hive = &g_Hives[0];
        }

        HiveAddress = Hive->HivePtr;
    }

    return ExtRemoteTyped("(nt!_HHIVE *)@$extin", HiveAddress);
}

BOOL
RegGetKeyValue(
    _In_ PWSTR FullKeyPath,
    _In_ PWSTR ValueName,
    _Out_ PVOID Data,
    _In_ ULONG DataLength
    )
{
    BOOL Status = FALSE;

    ZeroMemory(Data, DataLength);

    try {

        ExtRemoteTyped CmHive = GetHive(FullKeyPath);
        ExtRemoteTyped KeyNode = GetKeyNode(FullKeyPath);

        ULONG ValuesCount = KeyNode.Field("ValueList").Field("Count").GetUlong();

        if (ValuesCount) {

            PULONG ValuesTable = (PULONG)calloc(ValuesCount, sizeof(ULONG));

            if (ValuesTable) {

                ULONG ValuesIndex = KeyNode.Field("ValueList").Field("List").GetUlong();
                ULONG64 ValuesTableAddress = RegGetCellPaged(CmHive, ValuesIndex);

                if (ExtRemoteTypedEx::ReadVirtual(ValuesTableAddress, ValuesTable, ValuesCount * sizeof(ULONG), NULL) == S_OK) {

                    CHAR ValueNameAnsi[MAX_VALUE_NAME];
                    WCHAR ValueNameWide[MAX_VALUE_NAME];

                    for (UINT j = 0; j < ValuesCount; j++) {

                        ULONG64 KeyValueAddress = RegGetCellPaged(CmHive, ValuesTable[j]);

                        ExtRemoteTyped KeyValue("(nt!_CM_KEY_VALUE *)@$extin", KeyValueAddress);

                        USHORT NameLength = KeyValue.Field("NameLength").GetUshort();

                        if (NameLength) {

                            ZeroMemory(ValueNameAnsi, sizeof(ValueNameAnsi));

                            ULONG64 NameAddress = KeyValue.Field("Name").GetPointerTo().GetPtr();

                            ExtRemoteTypedEx::ReadVirtual(NameAddress, ValueNameAnsi, min(NameLength, sizeof(ValueNameAnsi) - 1), NULL);

                            StringCchPrintfW(ValueNameWide, _countof(ValueNameWide), L"%S", ValueNameAnsi);

                            if (0 == wcscmp(ValueName, ValueNameWide)) {

                                if (KeyValue.Field("Signature").GetUshort() == CM_KEY_VALUE_SIGNATURE) {

                                    ULONG ValueLength = (KeyValue.Field("DataLength").GetUlong()) & 0x7FFFFFFF;

                                    if (ValueLength <= DataLength) {

                                        switch (KeyValue.Field("Type").GetUlong()) {

                                        case REG_SZ:
                                        case REG_EXPAND_SZ:
                                        case REG_MULTI_SZ:
                                        case REG_BINARY:
                                        case REG_LINK:
                                        {
                                            ULONG64 ValueAddress = RegGetCellPaged(CmHive, KeyValue.Field("Data").GetUlong());

                                            if (ExtRemoteTypedEx::ReadVirtual(ValueAddress, Data, ValueLength, NULL) == S_OK) {

                                                Status = TRUE;
                                            }

                                            break;
                                        }
                                        case REG_DWORD:
                                        case REG_DWORD_BIG_ENDIAN:
                                        {
                                            *(PDWORD)Data = KeyValue.Field("Data").GetUlong();

                                            Status = TRUE;

                                            break;
                                        }
                                        case REG_QWORD:
                                        {
                                            *(PDWORD64)Data = KeyValue.Field("Data").GetLong64();

                                            Status = TRUE;

                                            break;
                                        }
                                        }
                                    }
                                }

                                break;
                            }
                        }
                    }
                }

                free(ValuesTable);
            }
        }
    }
    catch (...) {

    }

    return Status;
}

vector<KEY_NAME>
RegGetKeyValuesNames(
    _In_ PWSTR FullKeyPath
    )
{
    vector<KEY_NAME> KeyValuesNames;
    KEY_NAME ValueName;

    try {

        ExtRemoteTyped CmHive = GetHive(FullKeyPath);
        ExtRemoteTyped KeyNode = GetKeyNode(FullKeyPath);

        ULONG ValuesCount = KeyNode.Field("ValueList").Field("Count").GetUlong();

        if (ValuesCount) {

            PULONG ValuesTable = (PULONG)calloc(ValuesCount, sizeof(ULONG));

            if (ValuesTable) {

                ULONG ValuesIndex = KeyNode.Field("ValueList").Field("List").GetUlong();
                ULONG64 ValuesTableAddress = RegGetCellPaged(CmHive, ValuesIndex);

                if (ExtRemoteTypedEx::ReadVirtual(ValuesTableAddress, ValuesTable, ValuesCount * sizeof(ULONG), NULL) == S_OK) {

                    CHAR ValueNameAnsi[MAX_VALUE_NAME];
                    WCHAR ValueNameWide[MAX_VALUE_NAME];

                    for (UINT j = 0; j < ValuesCount; j++) {

                        ULONG64 KeyValueAddress = RegGetCellPaged(CmHive, ValuesTable[j]);

                        ExtRemoteTyped KeyValue("(nt!_CM_KEY_VALUE *)@$extin", KeyValueAddress);

                        USHORT NameLength = KeyValue.Field("NameLength").GetUshort();

                        if (NameLength) {

                            ZeroMemory(ValueNameAnsi, sizeof(ValueNameAnsi));

                            ULONG64 NameAddress = KeyValue.Field("Name").GetPointerTo().GetPtr();

                            ExtRemoteTypedEx::ReadVirtual(NameAddress, ValueNameAnsi, min(NameLength, sizeof(ValueNameAnsi) - 1), NULL);

                            StringCchPrintfW(ValueNameWide, _countof(ValueNameWide), L"%S", ValueNameAnsi);

                            StringCchCopyW(ValueName.Name, _countof(ValueName.Name), ValueNameWide);

                            KeyValuesNames.push_back(ValueName);
                        }
                    }
                }

                free(ValuesTable);
            }
        }
    }
    catch (...) {

    }

    return KeyValuesNames;
}

vector<KEY_NODE>
RegGetSubKeys(
    _In_ PWSTR FullKeyPath
    )
{
    vector<KEY_NODE> SubKeys;

    try {

        ExtRemoteTyped KeyHive = GetHive(FullKeyPath);
        ExtRemoteTyped KeyNode = GetKeyNode(FullKeyPath);

        SubKeys = GetSubKeys(KeyHive, KeyNode);
    }
    catch (...) {

    }

    return SubKeys;
}

ULONG64
RegGetCellPaged(
    _In_ ExtRemoteTyped KeyHive,
    _In_ ULONG CellIndex
)
/*++

Routine Description:

    Description.

Arguments:

     KeyHive - 
     CellIndex - 

Return Value:

    None.

--*/
{
    ULONG Type, Table, Block, Offset;
    ULONG64 CellAddr;

    Type = ((ULONG)((CellIndex & HCELL_TYPE_MASK) >> HCELL_TYPE_SHIFT));
    Table = (ULONG)((CellIndex & HCELL_TABLE_MASK) >> HCELL_TABLE_SHIFT);
    Block = (ULONG)((CellIndex & HCELL_BLOCK_MASK) >> HCELL_BLOCK_SHIFT);
    Offset = (ULONG)(CellIndex & HCELL_OFFSET_MASK);

    // g_Ext->Dml("Hive: %I64X, CellIndex = %x, Type = %x, Table = %x, Block = %x, Offset = %x\n",
    //    KeyHive.GetPtr(), CellIndex, Type, Table, Block, Offset);

    ExtRemoteTyped DirMap = KeyHive.Field("Storage").ArrayElement(Type).Field("Map");
    ExtRemoteTyped MapTable = DirMap.Field("Directory").ArrayElement(Table);

    if (MapTable.Field("Table").ArrayElement(Block).HasField("BlockAddress")) {

        CellAddr = MapTable.Field("Table").ArrayElement(Block).Field("BlockAddress").GetPtr();
    }
    else {

        CellAddr = MapTable.Field("Table").ArrayElement(Block).Field("PermanentBinAddress").GetPtr() & ~0xF;
    }

    CellAddr += Offset;
    if (KeyHive.Field("Version").GetUlong() == 1) CellAddr += sizeof(LONG)+sizeof(ULONG);
    else CellAddr += sizeof(LONG);

    return CellAddr;
}

VOID
RegReadKeyNode(
    _In_ ExtRemoteTyped KeyHive,
    _In_ ExtRemoteTyped KeyNode
)
/*++

Routine Description:

    Description.

Arguments:

     KeyHive - 
     KeyNode -

Return Value:

    None.

--*/
{
    CHAR Name[512] = {0};
    PULONG ValuesTable = NULL;
    PVOID SubKeysStableTable = NULL;
    PVOID SubKeysVolatileTable = NULL;
    ULONG64 SubKeysStableTableAddress;
    ULONG64 SubKeysVolatileTableAddress;
    ULONG64 ValuesTableAddress;
    ULONG64 NameAddress;
    USHORT NameLength;

    if (KeyNode.Field("Signature").GetUshort() == CM_LINK_NODE_SIGNATURE) {

        KeyHive = ExtRemoteTyped("(nt!_HHIVE *)@$extin", KeyNode.Field("ChildHiveReference.KeyHive").GetPtr());

        ULONG KeyCell = KeyNode.Field("ChildHiveReference.KeyCell").GetUlong();
        ULONG64 KeyNodeAddress = RegGetCellPaged(KeyHive, KeyCell);
        KeyNode = ExtRemoteTyped("(nt!_CM_KEY_NODE *)@$extin", KeyNodeAddress);
    }

    ULONG ValuesCount = KeyNode.Field("ValueList").Field("Count").GetUlong();
    ULONG ValuesIndex = KeyNode.Field("ValueList").Field("List").GetUlong();

    ULONG SubKeysStableCount = KeyNode.Field("SubKeyCounts").ArrayElement(0).GetUlong();
    ULONG SubKeysVolatileCount = KeyNode.Field("SubKeyCounts").ArrayElement(1).GetUlong();

    RtlZeroMemory(Name, sizeof(Name));

    NameLength = KeyNode.Field("NameLength").GetUshort();

    if (NameLength) {

        NameAddress = KeyNode.Field("Name").GetPointerTo().GetPtr();

        ExtRemoteTypedEx::ReadVirtual(NameAddress, Name, min(NameLength, sizeof(Name) - 1), NULL);
    }

    g_Ext->Dml(" Key node <col fg=\"changed\">%s</col> contains %d key values and %d subkeys.\n\n",
               Name,
               ValuesCount,
               SubKeysStableCount + SubKeysVolatileCount);

    if (SubKeysStableCount + SubKeysVolatileCount) g_Ext->Dml(" [*] Subkeys (%d):\n", SubKeysStableCount + SubKeysVolatileCount);

    if (SubKeysStableCount)
    {
        ULONG SubKeysStableIndex = KeyNode.Field("SubKeyLists").ArrayElement(0).GetUlong();

        SubKeysStableTableAddress = RegGetCellPaged(KeyHive, SubKeysStableIndex);

        ULONG MaxSize = sizeof(CM_KEY_FAST_INDEX) + SubKeysStableCount * sizeof(CM_INDEX);

        SubKeysStableTable = (PULONG)calloc(MaxSize, sizeof(BYTE));

        if (SubKeysStableTable) {

            if (ExtRemoteTypedEx::ReadVirtual(SubKeysStableTableAddress, SubKeysStableTable, MaxSize, NULL) == S_OK) {

                PCM_KEY_INDEX CmKeyIndex = (PCM_KEY_INDEX)SubKeysStableTable;

                for (UINT i = 0; i < SubKeysStableCount; i++) {

                    ULONG64 Address = 0;
                    CHAR TimeBuffer[128] = {0};
                    FILETIME LastWriteTime = {0};

                    try {

                        if ((CmKeyIndex->Signature == CM_INDEX_ROOT_SIGNATURE) || (CmKeyIndex->Signature == CM_INDEX_LEAF_SIGNATURE)) {

                            Address = RegGetCellPaged(KeyHive, CmKeyIndex->CellIndex[i]);
                        }
                        else if ((CmKeyIndex->Signature == CM_FAST_LEAF_SIGNATURE) || (CmKeyIndex->Signature == CM_HASH_LEAF_SIGNATURE)) {

                            PCM_KEY_FAST_INDEX CmKeyFastIndex = (PCM_KEY_FAST_INDEX)CmKeyIndex;
                            Address = RegGetCellPaged(KeyHive, CmKeyFastIndex->Index[i].CellIndex);
                        }

                        ExtRemoteTyped LocalKeyNode("(nt!_CM_KEY_NODE *)@$extin", Address);

                        LastWriteTime.dwLowDateTime = LocalKeyNode.Field("LastWriteTime.LowPart").GetUlong();
                        LastWriteTime.dwHighDateTime = LocalKeyNode.Field("LastWriteTime.HighPart").GetUlong();

                        RtlZeroMemory(Name, sizeof(Name));

                        NameLength = LocalKeyNode.Field("NameLength").GetUshort();

                        if (NameLength) {

                            NameAddress = LocalKeyNode.Field("Name").GetPointerTo().GetPtr();

                            ExtRemoteTypedEx::ReadVirtual(NameAddress, Name, min(NameLength, sizeof(Name) - 1), NULL);
                        }

                        g_Ext->Dml("   [%2d] <link cmd=\"!ms_readknode 0x%I64X 0x%I64X\">0x%I64X</link> | <col fg=\"changed\">%-50s</col> | LastWriteTime: %s\n",
                                   i,
                                   KeyHive.GetPtr(),
                                   Address,
                                   Address,
                                   Name,
                                   GetLastWriteTime(&LastWriteTime, TimeBuffer, sizeof(TimeBuffer)));
                    }
                    catch (...) {

                    }
                }
            }

            free(SubKeysStableTable);
        }
    }

    if (SubKeysVolatileCount)
    {
        ULONG SubKeysVolatileIndex = KeyNode.Field("SubKeyLists").ArrayElement(1).GetUlong();

        SubKeysVolatileTableAddress = RegGetCellPaged(KeyHive, SubKeysVolatileIndex);

        ULONG MaxSize = sizeof(CM_KEY_FAST_INDEX) + SubKeysVolatileCount * sizeof(CM_INDEX);

        SubKeysVolatileTable = (PULONG)calloc(MaxSize, sizeof(BYTE));

        if (SubKeysVolatileTable) {

            if (ExtRemoteTypedEx::ReadVirtual(SubKeysVolatileTableAddress, SubKeysVolatileTable, MaxSize, NULL) == S_OK) {

                PCM_KEY_INDEX CmKeyIndex = (PCM_KEY_INDEX)SubKeysVolatileTable;

                for (UINT i = 0; i < SubKeysVolatileCount; i++) {

                    ULONG64 Address = 0;

                    try {

                        if ((CmKeyIndex->Signature == CM_INDEX_ROOT_SIGNATURE) || (CmKeyIndex->Signature == CM_INDEX_LEAF_SIGNATURE)) {

                            Address = RegGetCellPaged(KeyHive, CmKeyIndex->CellIndex[i]);
                        }
                        else if ((CmKeyIndex->Signature == CM_FAST_LEAF_SIGNATURE) || (CmKeyIndex->Signature == CM_HASH_LEAF_SIGNATURE)) {

                            PCM_KEY_FAST_INDEX CmKeyFastIndex = (PCM_KEY_FAST_INDEX)CmKeyIndex;
                            Address = RegGetCellPaged(KeyHive, CmKeyFastIndex->Index[i].CellIndex);
                        }

                        ExtRemoteTyped LocalKeyNode("(nt!_CM_KEY_NODE *)@$extin", Address);

                        RtlZeroMemory(Name, sizeof(Name));

                        NameLength = LocalKeyNode.Field("NameLength").GetUshort();

                        if (NameLength) {

                            NameAddress = LocalKeyNode.Field("Name").GetPointerTo().GetPtr();

                            ExtRemoteTypedEx::ReadVirtual(NameAddress, Name, min(NameLength, sizeof(Name) - 1), NULL);
                        }

                        g_Ext->Dml("   [%2d] <link cmd=\"!ms_readknode 0x%I64X 0x%I64X\">0x%I64X</link> | <col fg=\"changed\">%-32s</col>\n",
                                   i,
                                   KeyHive.GetPtr(),
                                   Address,
                                   Address,
                                   Name);
                    }
                    catch (...) {

                    }
                }
            }

            free(SubKeysVolatileTable);
        }
    }

    g_Ext->Dml("\n");

    if (ValuesCount) {

        ValuesTableAddress = RegGetCellPaged(KeyHive, ValuesIndex);

        ValuesTable = (PULONG)calloc(ValuesCount * sizeof(ULONG), sizeof(BYTE));

        if (ValuesTable) {

            if (ExtRemoteTypedEx::ReadVirtual(ValuesTableAddress, ValuesTable, ValuesCount * sizeof(ULONG), NULL) == S_OK) {

                g_Ext->Dml(" [*] Values (%d):\n", ValuesCount);

                for (UINT i = 0; i < ValuesCount; i++) {

                    try {

                        ULONG64 Address = RegGetCellPaged(KeyHive, ValuesTable[i]);

                        ExtRemoteTyped KeyValue("(nt!_CM_KEY_VALUE *)@$extin", Address);

                        NameLength = 0;

                        RtlZeroMemory(Name, sizeof(Name));

                        if (KeyValue.GetPtr()) {

                            NameLength = KeyValue.Field("NameLength").GetUshort();

                            if (NameLength) {

                                NameAddress = KeyValue.Field("Name").GetPointerTo().GetPtr();

                                ExtRemoteTypedEx::ReadVirtual(NameAddress, Name, min(NameLength, sizeof(Name) - 1), NULL);
                            }
                        }

                        g_Ext->Dml("   [%2d] <link cmd=\"!ms_readkvalue 0x%I64X 0x%I64X\">0x%I64X</link> | <col fg=\"changed\">%-32s</col> | ",
                                   i,
                                   KeyHive.GetPtr(),
                                   Address,
                                   Address,
                                   NameLength ? Name : "(Default)");

                        g_Ext->Dml("        ");

                        RegReadKeyValue(KeyHive, KeyValue);
                    }
                    catch (...) {

                    }
                }

                g_Ext->Dml("\n");
            }

            free(ValuesTable);
        }
    }
}

LPWSTR
RegGetKeyName(
    _In_ ExtRemoteTyped KeyControlBlock
)
/*++

Routine Description:

    Description.

Arguments:

     KeyControlBlock - 

Return Value:

    LPWSTR.

--*/
{
    CHAR Children[64] = { 0 };
    LPWSTR FullNameA = NULL, TmpName = NULL;

    BOOLEAN Result = FALSE;

    ExtRemoteTyped Kcb = KeyControlBlock;

    ULONG64 ParentKcb;
    ULONG AllocateSize = (MAX_PATH + 1) * sizeof(FullNameA[0]);

    FullNameA = (LPWSTR)malloc(AllocateSize);
    TmpName = (LPWSTR)malloc(AllocateSize);

    if (!FullNameA || !TmpName) goto CleanUp;

    RtlZeroMemory(TmpName, AllocateSize);
    RtlZeroMemory(FullNameA, AllocateSize);

    try {

        while (1) {

            USHORT MaxLen = Kcb.Field("NameBlock").Field("NameLength").GetUshort();
            if (MaxLen >= sizeof(Children)) goto CleanUp;

            RtlZeroMemory(Children, sizeof(Children));
            if (g_Ext->m_Data->ReadVirtual(Kcb.Field("NameBlock").Field("Name").GetPointerTo().GetPtr(),
                                           (PSTR)Children,
                                           MaxLen,
                                           NULL) != S_OK) goto CleanUp;

            StringCchPrintfW(FullNameA, MAX_PATH, L"%s\\%S", TmpName, Children);
            StringCchCopyW(TmpName, MAX_PATH, FullNameA);

            ParentKcb = Kcb.Field("ParentKcb").GetPtr();
            if (!ParentKcb) break;
            Kcb = ExtRemoteTyped("(nt!_CM_KEY_CONTROL_BLOCK *)@$extin", ParentKcb);
        }
    }
    catch (...) {

    }

    Result = TRUE;

CleanUp:

    if (!Result) {

        if (FullNameA) {

            free(FullNameA);

            FullNameA = NULL;
        }
    }

    if (TmpName) {

        free(TmpName);

        TmpName = NULL;
    }

    return FullNameA;
}

VOID
RegReadKeyValue(
    ExtRemoteTyped KeyHive,
    ExtRemoteTyped KeyValue
)
/*++

Routine Description:

    Description.

Arguments:

    KeyHive - 
    KeyValue - 

Return Value:

    None.

--*/
{
    PUCHAR Buffer = NULL;
    ULONG64 Data;
    UINT i;

    if (KeyValue.Field("Signature").GetUshort() != CM_KEY_VALUE_SIGNATURE)
    {
        g_Ext->Err("Error: Invalid object (o=%I64X) signature.\n", KeyValue.GetPtr());
        goto CleanUp;
    }

    ULONG DataLength = (KeyValue.Field("DataLength").GetUlong()) & 0x7FFFFFFF;

    Buffer = (PUCHAR)calloc(DataLength + sizeof(WCHAR), sizeof(BYTE));

    if (Buffer) {

        switch (KeyValue.Field("Type").GetUlong())
        {
            case REG_BINARY:
                Data = RegGetCellPaged(KeyHive, KeyValue.Field("Data").GetUlong());
                if (ExtRemoteTypedEx::ReadVirtual(Data, Buffer, DataLength, NULL) != S_OK) goto CleanUp;

                g_Ext->Dml("\n        REG_BINARY: \n        ");
                for (i = 0; i < DataLength; i += 1)
                {
                    UINT j;
                    for (j = 0; (i + j < DataLength) && (j < 0x10); j += 1)
                    {
                        g_Ext->Dml("0x%02x ", Buffer[i + j]);
                    }

                    for (; j < 0x10; j += 1) g_Ext->Dml("     ");

                    g_Ext->Dml(" | ");
                    for (j = 0; (i + j < DataLength) && (j < 0x10); j += 1)
                    {
                        g_Ext->Dml("%c ", ((Buffer[i + j] >= ' ') && (Buffer[i + j] <= 'Z')) ? Buffer[i + j] : '.');
                    }

                    g_Ext->Dml("\n        ");

                    i += j;
                }
                if (((i + 1) % 0x10) != 0) g_Ext->Dml("\n");
            break;
            case REG_DWORD:
                g_Ext->Dml("0x%08X (REG_DWORD)\n", KeyValue.Field("Data").GetUlong());
                break;
            case REG_DWORD_BIG_ENDIAN:
                g_Ext->Dml("0x%08X (REG_DWORD_BIG_ENDIAN)\n", KeyValue.Field("Data").GetUlong());
                break;
            case REG_EXPAND_SZ:
                Data = RegGetCellPaged(KeyHive, KeyValue.Field("Data").GetUlong());
                if (ExtRemoteTypedEx::ReadVirtual(Data, Buffer, DataLength, NULL) != S_OK) goto CleanUp;

                g_Ext->Dml("%S (REG_EXPAND_SZ)\n", Buffer);
                break;
            case REG_LINK:
                Data = RegGetCellPaged(KeyHive, KeyValue.Field("Data").GetUlong());
                if (ExtRemoteTypedEx::ReadVirtual(Data, Buffer, DataLength, NULL) != S_OK) goto CleanUp;

                g_Ext->Dml("%S (REG_LINK)\n", Buffer);
                break;
            case REG_MULTI_SZ:
                Data = RegGetCellPaged(KeyHive, KeyValue.Field("Data").GetUlong());
                if (ExtRemoteTypedEx::ReadVirtual(Data, Buffer, DataLength, NULL) != S_OK) goto CleanUp;

                g_Ext->Dml("%S (REG_MULTI_SZ)\n", Buffer);
                break;
            case REG_NONE:
                break;
            case REG_QWORD:
                g_Ext->Dml("0x%I64X (REG_QWORD)\n", KeyValue.Field("Data").GetLong64());
                break;
            case REG_SZ:
                Data = RegGetCellPaged(KeyHive, KeyValue.Field("Data").GetUlong());
                if (ExtRemoteTypedEx::ReadVirtual(Data, Buffer, DataLength, NULL) != S_OK) goto CleanUp;

                g_Ext->Dml("%S (REG_SZ)\n", Buffer);
            break;
        }
    }

CleanUp:
    if (Buffer) free(Buffer);
}

vector<HIVE_OBJECT>
GetHives(
)
/*++

Routine Description:

    Description.

Arguments:

     - 

Return Value:

    vector<HIVE_OBJECT>.

--*/
{
    ULONG64 CmpHiveListHead;
    vector<HIVE_OBJECT> Hives;

    CmpHiveListHead = GetExpression("nt!CmpHiveListHead");

    ExtRemoteTypedList HiveList(CmpHiveListHead, "nt!_CMHIVE", "HiveList");

    try {

        for (HiveList.StartHead(); HiveList.HasNode(); HiveList.Next()) {

            HIVE_OBJECT HiveObject = {0};

            if (HiveList.GetTypedNode().Field("Hive.Signature").GetUlong() != CM_HIVE_SIGNATURE) break;

            ExtRemoteTypedEx::GetUnicodeString(HiveList.GetTypedNode().Field("FileUserName"), (PWSTR)&HiveObject.FileUserName, sizeof(HiveObject.FileUserName));
            ExtRemoteTypedEx::GetUnicodeString(HiveList.GetTypedNode().Field("HiveRootPath"), (PWSTR)&HiveObject.HiveRootPath, sizeof(HiveObject.HiveRootPath));

            HiveObject.HivePtr = HiveList.GetNodeOffset();
            HiveObject.KeyNodePtr = GetKeyNode(HiveObject.HiveRootPath).m_Data;
            HiveObject.GetCellRoutine = HiveList.GetTypedNode().Field("Hive.GetCellRoutine").GetPtr();
            HiveObject.Allocate = HiveList.GetTypedNode().Field("Hive.Allocate").GetPtr();
            HiveObject.Free = HiveList.GetTypedNode().Field("Hive.Free").GetPtr();
            HiveObject.FileWrite = HiveList.GetTypedNode().Field("Hive.FileWrite").GetPtr();
            HiveObject.FileRead = HiveList.GetTypedNode().Field("Hive.FileRead").GetPtr();

            if (HiveList.GetTypedNode().HasField("Flags")) {

                HiveObject.Flags = HiveList.GetTypedNode().Field("Flags").GetUlong();
            }

            if (HiveList.GetTypedNode().HasField("Hive.ReleaseCellRoutine")) {

                HiveObject.ReleaseCellRoutine = HiveList.GetTypedNode().Field("Hive.ReleaseCellRoutine").GetPtr();
            }

            if (HiveList.GetTypedNode().HasField("Hive.FileSetSize")) {

                HiveObject.FileSetSize = HiveList.GetTypedNode().Field("Hive.FileSetSize").GetPtr();
            }

            if (HiveList.GetTypedNode().HasField("Hive.FileFlush")) {

                HiveObject.FileFlush = HiveList.GetTypedNode().Field("Hive.FileFlush").GetPtr();
            }

            Hives.push_back(HiveObject);
        }
    }
    catch (...) {

    }

    return Hives;
}

BOOL
RegInitialize(
    VOID
    )
{
    g_Hives = GetHives();

    return g_Hives.size() ? TRUE : FALSE;
}
