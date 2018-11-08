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

    - Ob.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx


Environment:

    - User mode

Revision History:

    - Matthieu Suiche
--*/

#include "stdafx.h"
#include "SwishDbgExt.h"

BOOLEAN ObTypeInit = FALSE;
ExtRemoteTyped ObjTypeTable;


BOOLEAN
ObReadObject(
    _In_ ULONG64 Object,
    _Out_ PHANDLE_OBJECT HandleObj
)
/*++

Routine Description:

    Description.

Arguments:

    Object - 
    HandleObj - 

Return Value:

    BOOLEAN.

--*/
{
    BOOLEAN Result = FALSE;
    PWSTR ObjectName = NULL;
    WCHAR TypeStr[64] = {0};
    ULONG BodyOffset = 0;

    GetFieldOffset("nt!_OBJECT_HEADER", "Body", &BodyOffset);

    try {

        ZeroMemory(HandleObj, sizeof(HANDLE_OBJECT));

        if ((!Object) || (!IsValid(Object))) return FALSE;

        if (!ObTypeInit)
        {
            ObjTypeTable = ExtRemoteTyped("(nt!_OBJECT_TYPE **)@$extin", ObTypeIndexTableAddress);
            ObTypeInit = TRUE;
        }

        ULONG64 ObjHeaderAddr = Object - BodyOffset;

        if (!IsValid(ObjHeaderAddr)) return FALSE;

        ExtRemoteTyped ObjHeader("(nt!_OBJECT_HEADER *)@$extin", ObjHeaderAddr);
        HandleObj->ObjectPtr = Object; // ObjHeader.Field("Body").GetPointerTo().GetPtr();

        if (ObjHeader.HasField("TypeIndex"))
        {
            BYTE HeaderCookie;

            HandleObj->ObjectTypeIndex = ObjHeader.Field("TypeIndex").GetUchar();

            if (g_Ext->m_Data->ReadVirtual(ObHeaderCookieAddress, &HeaderCookie, sizeof(HeaderCookie), NULL) == S_OK) {

                HandleObj->ObjectTypeIndex = (((ObjHeaderAddr >> 8) & 0xff) ^ HandleObj->ObjectTypeIndex) ^ HeaderCookie;
            }

            ExtRemoteTypedEx::GetUnicodeString(ObjTypeTable.ArrayElement(HandleObj->ObjectTypeIndex).Field("Name"), TypeStr, sizeof(TypeStr));

            StringCchCopyW(HandleObj->Type, _countof(HandleObj->Type), TypeStr);
        }
        else
        {
            if (!IsValid(ObjHeader.Field("Type").GetPtr())) goto CleanUp;

            ExtRemoteTypedEx::GetUnicodeString(ObjHeader.Field("Type").Field("Name"), TypeStr, sizeof(TypeStr));

            StringCchCopyW(HandleObj->Type, _countof(HandleObj->Type), TypeStr);
        }

        if (_wcsicmp(TypeStr, L"File") == 0)
        {
            ExtRemoteTyped FileObject("(nt!_FILE_OBJECT *)@$extin", HandleObj->ObjectPtr);
            ObjectName = ExtRemoteTypedEx::GetUnicodeString2(FileObject.Field("FileName"));
        }
        else if (_wcsicmp(TypeStr, L"Driver") == 0)
        {
            ExtRemoteTyped DrvObject("(nt!_DRIVER_OBJECT *)@$extin", HandleObj->ObjectPtr);
            ObjectName = ExtRemoteTypedEx::GetUnicodeString2(DrvObject.Field("DriverName"));
        }
        else if (_wcsicmp(TypeStr, L"Process") == 0)
        {
            CHAR Buffer[MAX_PATH] = {0};

            ExtRemoteTyped ProcessObj("(nt!_EPROCESS *)@$extin", HandleObj->ObjectPtr);

            ProcessObj.Field("ImageFileName").GetString(Buffer, ProcessObj.Field("ImageFileName").GetTypeSize());

            if (strlen(Buffer)) {

                StringCchPrintfW(HandleObj->Name, _countof(HandleObj->Name), L"%S", Buffer);
            }
        }
        //else if (_wcsicmp(TypeStr, L"ALPC Port") == 0)
        //{
        //    // dt nt!_ALPC_PORT
        //}
        //else if (_wcsicmp(TypeStr, L"EtwRegistration") == 0)
        //{
        //    // dt nt!_ETW_?
        //}
        else if (_wcsicmp(TypeStr, L"Thread") == 0)
        {
            // dt nt!_ETHREAD
        }
        //else if (_wcsicmp(TypeStr, L"Event") == 0)
        //{
        //    // dt nt!_KTHREAD
        //}
        else if (_wcsicmp(TypeStr, L"Key") == 0)
        {
            ExtRemoteTyped KeyObject("(nt!_CM_KEY_BODY *)@$extin", HandleObj->ObjectPtr);
            HandleObj->ObjectKcb = KeyObject.Field("KeyControlBlock").GetPtr();
            ObjectName = RegGetKeyName(HandleObj->ObjectKcb);
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
                ObjectName = ExtRemoteTypedEx::GetUnicodeString2(ObjNameInfo.Field("Name"));
            }
        }
    }
    catch (...) {

    }

    if (ObjectName)
    {
        StringCchCopyW(HandleObj->Name, _countof(HandleObj->Name), ObjectName);

        free(ObjectName);
        ObjectName = NULL;
    }

    Result = TRUE;

CleanUp:

    return Result;
}

vector<HANDLE_OBJECT>
ObOpenObjectDirectory(
    _In_ ULONG64 InputObject
)
/*++

Routine Description:

    Description.

Arguments:

    InputObject - 

Return Value:

    vector<HANDLE_OBJECT>.

--*/
{
    vector<HANDLE_OBJECT> Handles;
    vector<ULONG64> Nodes;
    HANDLE_OBJECT Handle = {0};
    ExtRemoteTyped Directory;
    ULONG64 ObjectDir = InputObject;

    try {

        if (!ObjectDir) {

            ReadPointer(ObpRootDirectoryObjectAddress, &ObjectDir);
        }

        Directory = ExtRemoteTyped("(nt!_OBJECT_DIRECTORY *)@$extin", ObjectDir);

        ObReadObject(ObjectDir, &Handle);

        for (UINT i = 0; i < 37; i += 1) {

            ULONG64 Entry = Directory.Field("HashBuckets").ArrayElement(i).GetPointerTo().GetPtr();

            if (!Entry) {

                continue;
            }

            //
            // ExtRemoteTypedList requires a POINTER to the first entry. Not the offset of the first entry.
            //

            ExtRemoteTypedList EntryList(Entry, "nt!_OBJECT_DIRECTORY_ENTRY", "ChainLink");

            for (EntryList.StartHead(); EntryList.HasNode(); EntryList.Next()) {

                ULONG64 Object = EntryList.GetTypedNode().Field("Object").GetPtr();

                if (find(Nodes.rbegin(), Nodes.rend(), Object) != Nodes.rend()) {

                    break;
                }

                Nodes.push_back(Object);

                ObReadObject(Object, &Handle);

                Handles.push_back(Handle);
            }
        }
    }
    catch (...) {

    }

    return Handles;
}

BOOLEAN
ObOpenChildren(
    _In_opt_ ULONG64 Root,
    _In_ LPWSTR ObjName,
    _Out_ PHANDLE_OBJECT OutHandle
)
/*++

Routine Description:

    Description.

Arguments:

    Root - 
    ObjName -
    OutHandle -

Return Value:

    BOOLEAN.

--*/
{
    vector<HANDLE_OBJECT> Dir = ObOpenObjectDirectory(Root);
    BOOLEAN Result = FALSE;

    ZeroMemory(OutHandle, sizeof(HANDLE_OBJECT));

    for each (HANDLE_OBJECT Handle in Dir)
    {
        if (_wcsicmp(Handle.Name, ObjName) == 0)
        {
            *OutHandle = Handle;
            Result = TRUE;
            break;
        }
    }

    return Result;
}

ULONG64
ObGetFileSystemObject(
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
    ULONG64 Object = 0;

    HANDLE_OBJECT Handle;
    if (ObOpenChildren(0, L"FileSystem", &Handle)) Object = Handle.ObjectPtr;

    return Object;
}

ULONG64
ObGetObjectTypesObject(
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
    ULONG64 Object = 0;

    HANDLE_OBJECT Handle;
    if (ObOpenChildren(0, L"ObjectTypes", &Handle)) Object = Handle.ObjectPtr;

    return Object;
}

ULONG64
ObGetDriverObject(
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
    ULONG64 Object = 0;;

    HANDLE_OBJECT Handle;
    if (ObOpenChildren(0, L"Driver", &Handle)) Object = Handle.ObjectPtr;

    return Object;
}

VOID
ReleaseObjectTypeTable(
    VOID
    )
{
    if (ObTypeInit) {

        ObjTypeTable.Release();

        ObTypeInit = FALSE;
    }
}
