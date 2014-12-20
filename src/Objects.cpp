/*++
MoonSols Incident Response & Digital Forensics Debugging Extension
Copyright (C) 2014 MoonSols Ltd. All rights reserved.

Module Name:

- Ob.cpp

Abstract:

- http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx


Environment:

- User mode

Revision History:

- Matthieu Suiche
--*/

#include "MoonSolsDbgExt.h"

BOOLEAN ObTypeInit = FALSE;
ExtRemoteTyped ObjTypeTable;

BOOLEAN
ObReadObject(
IN ULONG64 Object,
OUT PHANDLE_OBJECT HandleObj
)
{
    BOOLEAN Result = FALSE;
    LPWSTR ObjName = NULL;

    ULONG BodyOffset = 0;
    GetFieldOffset("nt!_OBJECT_HEADER", "Body", &BodyOffset);

    WCHAR TypeStr[64] = { 0 };

    if ((!Object) || (!IsValid(Object))) return FALSE;

    if (!ObTypeInit)
    {
        ObjTypeTable = ExtRemoteTyped("(nt!_OBJECT_TYPE **)@$extin", GetExpression("nt!ObTypeIndexTable"));
        ObTypeInit = TRUE;
    }

    ULONG64 ObjHeaderAddr = Object - BodyOffset;

    if (!IsValid(ObjHeaderAddr)) return FALSE;

    ExtRemoteTyped ObjHeader("(nt!_OBJECT_HEADER *)@$extin", ObjHeaderAddr);
    HandleObj->ObjectPtr = Object; // ObjHeader.Field("Body").GetPointerTo().GetPtr();

    if (ObjHeader.HasField("TypeIndex"))
    {
        HandleObj->ObjectTypeIndex = ObjHeader.Field("TypeIndex").GetChar();
        if ((HandleObj->ObjectTypeIndex <= 1) || (HandleObj->ObjectTypeIndex >= 45)) return FALSE;

        ExtRemoteTypedEx::GetUnicodeString(ObjTypeTable.ArrayElement(HandleObj->ObjectTypeIndex).Field("Name"), TypeStr, sizeof(TypeStr));
        wcscpy_s(HandleObj->Type, TypeStr);
    }
    else
    {
        if (!IsValid(ObjHeader.Field("Type").GetPtr())) goto CleanUp;

        ExtRemoteTypedEx::GetUnicodeString(ObjHeader.Field("Type").Field("Name"), TypeStr, sizeof(TypeStr));
        wcscpy_s(HandleObj->Type, TypeStr);
    }

    if (_wcsicmp(TypeStr, L"File") == 0)
    {
        ExtRemoteTyped FileObject("(nt!_FILE_OBJECT *)@$extin", HandleObj->ObjectPtr);
        ObjName = ExtRemoteTypedEx::GetUnicodeString2(FileObject.Field("FileName"));
    }
    else if (_wcsicmp(TypeStr, L"Driver") == 0)
    {
        ExtRemoteTyped DrvObject("(nt!_DRIVER_OBJECT *)@$extin", HandleObj->ObjectPtr);
        ObjName = ExtRemoteTypedEx::GetUnicodeString2(DrvObject.Field("DriverName"));
    }
    else if (_wcsicmp(TypeStr, L"Process") == 0)
    {
        ExtRemoteTyped ProcessObj("(nt!_EPROCESS *)@$extin", HandleObj->ObjectPtr);
        ObjName = ExtRemoteTypedEx::GetUnicodeString2(ProcessObj.Field("ImageFileName"));
    }
    else if (_wcsicmp(TypeStr, L"ALPC Port") == 0)
    {
        // dt nt!_ALPC_PORT
    }
    else if (_wcsicmp(TypeStr, L"EtwRegistration") == 0)
    {
        // dt nt!_ETW_?
    }
    else if (_wcsicmp(TypeStr, L"Thread") == 0)
    {
        // dt nt!_ETHREAD
    }
    else if (_wcsicmp(TypeStr, L"Event") == 0)
    {
        // dt nt!_KTHREAD
    }
    else if (_wcsicmp(TypeStr, L"Key") == 0)
    {
        ExtRemoteTyped KeyObject("(nt!_CM_KEY_BODY *)@$extin", HandleObj->ObjectPtr);
        HandleObj->ObjectKcb = KeyObject.Field("KeyControlBlock").GetPtr();
        ObjName = RegGetKeyName(KeyObject.Field("KeyControlBlock"));
        // dt nt!_CM_KEY_BODY -> nt!_CM_KEY_CONTROL_BLOCK
    }
    else
    {
        ULONG Offset = 0;
        UCHAR InfoMask = 0;

        if (ObjHeader.HasField("InfoMask"))
        {
            InfoMask = ObjHeader.Field("InfoMask").GetUchar();

            if (InfoMask & OBP_NAME_INFO_BIT)
            {
                if (InfoMask & OBP_CREATOR_INFO_BIT) Offset += GetTypeSize("nt!_OBJECT_HEADER_CREATOR_INFO");
                Offset += GetTypeSize("nt!_OBJECT_HEADER_NAME_INFO");
            }
        }
        else
        {
            Offset = ObjHeader.Field("NameInfoOffset").GetUchar();
        }

        if (Offset)
        {
            ExtRemoteTyped ObjNameInfo("(nt!_OBJECT_HEADER_NAME_INFO *)@$extin", ObjHeaderAddr - Offset);
            ObjName = ExtRemoteTypedEx::GetUnicodeString2(ObjNameInfo.Field("Name"));
        }
    }

    if (ObjName)
    {
        wcscpy_s(HandleObj->Name, ObjName);
        free(ObjName);
        ObjName = NULL;
    }

    Result = TRUE;
CleanUp:
    return Result;
}

vector<HANDLE_OBJECT>
ObOpenObjectDirectory(
    ULONG64 InputObject
)
{
    vector<HANDLE_OBJECT> Handles;
    HANDLE_OBJECT Handle = { 0 };
    ExtRemoteTyped Directory;

    ULONG64 ObjectDir = InputObject;

    if (!ObjectDir)
    {
        ReadPointer(GetExpression("nt!ObpRootDirectoryObject"), &ObjectDir);
    }

    Directory = ExtRemoteTyped("(nt!_OBJECT_DIRECTORY *)@$extin", ObjectDir);

    ObReadObject(ObjectDir, &Handle);

    for (UINT i = 0; i < 37; i += 1)
    {
        ULONG64 Entry = Directory.Field("HashBuckets").ArrayElement(i).GetPointerTo().GetPtr();
        if (!Entry) continue;

        //
        // ExtRemoteTypedList requires a POINTER to the first entry. Not the offset of the first entry.
        //
        ExtRemoteTypedList EntryList(Entry, "nt!_OBJECT_DIRECTORY_ENTRY", "ChainLink");

        for (EntryList.StartHead(); EntryList.HasNode(); EntryList.Next())
        {
            HANDLE_OBJECT Handle = {0};

            ULONG64 Object = EntryList.GetTypedNode().Field("Object").GetPtr();
            ObReadObject(Object, &Handle);

            Handles.push_back(Handle);
        }
    }

    return Handles;
}

BOOLEAN
ObOpenChildren(
    OPTIONAL IN ULONG64 Root,
    IN LPWSTR ObjName,
    OUT PHANDLE_OBJECT OutHandle
)
{
    vector<HANDLE_OBJECT> Dir = ObOpenObjectDirectory(Root);
    BOOLEAN Result = FALSE;

    for each (HANDLE_OBJECT Handle in Dir)
    {
        if (_wcsicmp(Handle.Name, ObjName) == 0)
        {
            *OutHandle = Handle;
            Result = TRUE;
        }
    }

    return Result;
}

ULONG64
ObGetDriverObject(
)
{
    ULONG64 Object = 0;;

    HANDLE_OBJECT Handle;
    if (ObOpenChildren(0, L"Driver", &Handle)) Object = Handle.ObjectPtr;

    return Object;
}