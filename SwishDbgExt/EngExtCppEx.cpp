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

    - EngExtCppEx.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"

LPWSTR
ExtRemoteTypedEx::GetUnicodeString2(
ExtRemoteTyped TypedObject
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    LPWSTR.

--*/
{
    LPWSTR String = NULL;

#if VERBOSE_MODE
    // TypedObject.OutFullValue();
#endif

    USHORT MaxLen = TypedObject.Field("MaximumLength").GetUshort();
    USHORT Len = TypedObject.Field("Length").GetUshort();
    if ((MaxLen == 0) || (Len == 0)) return NULL;

    MaxLen = max(MaxLen, Len);
    MaxLen += sizeof(WCHAR);

    String = (LPWSTR)malloc(MaxLen);
    if (!String) return NULL;

    return GetUnicodeString(TypedObject, String, MaxLen);
}

LPWSTR
ExtRemoteTypedEx::GetUnicodeString(
    ExtRemoteTyped TypedObject,
    _Out_writes_(MaxChars) PWSTR Buffer,
    _In_ ULONG MaxChars
)
/*++

Routine Description:

    Description.

Arguments:

    TypedObject - 
    Buffer - 
    MaxChars - 

Return Value:

    LPWSTR.

--*/
{
    UNICODE_STRING SavedUnicodeString = {0};

    RtlZeroMemory(Buffer, MaxChars);

    SavedUnicodeString.Length = TypedObject.Field("Length").GetUshort();
    SavedUnicodeString.MaxLength = TypedObject.Field("MaximumLength").GetUshort();
    SavedUnicodeString.Buffer = TypedObject.Field("Buffer").GetPtr();

    if (SavedUnicodeString.Buffer && IsValid(SavedUnicodeString.Buffer) && SavedUnicodeString.Length)
    {
        if (SavedUnicodeString.Length > MaxChars)
        {
            /*
            g_Ext->ThrowRemote(HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW),
                               "(%s): String at %I64X overflows buffer, need 0x%x (Max = 0x%x) chars",
                               __FUNCTION__, TypedObject.m_Offset, SavedUnicodeString.Length, MaxChars);
            */
            SavedUnicodeString.Length = (USHORT)MaxChars;
            SavedUnicodeString.MaxLength = (USHORT)MaxChars;
        }

        if (g_Ext->m_Data->ReadVirtual(SavedUnicodeString.Buffer,
                                       (PWSTR)Buffer,
                                       SavedUnicodeString.Length,
                                       NULL) != S_OK)
        {
            // g_Ext->Dml("Error: Can't read buffer at 0x%I64X\n", SavedUnicodeString.Buffer);
            wcscpy_s(Buffer, MaxChars / sizeof(Buffer[0]), L"#ERROR#"); // _countof
        }
    }

    return Buffer;
}

LPWSTR
ExtRemoteTypedEx::GetUnicodeStringEx(
    ULONG64 UntypedObject,
    _Out_writes_opt_(MaxChars) PWSTR Buffer,
    _In_ ULONG MaxChars
)
/*++

Routine Description:

    Description.

Arguments:

    UntypedObject - 
    Buffer - 
    MaxChars - 

Return Value:

    LPWSTR.

--*/
{
    ExtRemoteTyped TypedObject("(nt!_UNICODE_STRING *)@$extin", UntypedObject);

    return ExtRemoteTypedEx::GetUnicodeString(TypedObject, Buffer, MaxChars);
}

LPWSTR
ExtRemoteTypedEx::GetString(
    ULONG64 Address,
    _Out_writes_(MaxChars) LPWSTR Buffer,
    _In_ ULONG MaxChars
)
/*++

Routine Description:

    Description.

Arguments:

    - Address
    - Buffer
    - MaxChars

Return Value:

    LPWSTR.

--*/
{
    RtlZeroMemory(Buffer, MaxChars);

    if (IsValid(Address))
    {
        ExtRemoteData usData(Address, MaxChars);
        usData.GetString(Buffer, MaxChars / sizeof(*Buffer));
    }

    return Buffer;
}

BOOLEAN
IsValid(
    _In_ ULONG64 Pointer
)
/*++

Routine Description:

    Description.

Arguments:

    Pointer - 

Return Value:

    BOOLEAN.

--*/
{
    UCHAR Buffer[4];
    ULONG BytesRead;

    HRESULT hResult = g_Ext->m_Data->ReadVirtual(Pointer, Buffer, sizeof(Buffer), &BytesRead);
    if (hResult != S_OK) return FALSE;

    return TRUE;
}

HRESULT
ExtRemoteTypedEx::ReadVirtual(
    _In_ ULONG64 BaseAddress,
    _Out_writes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG OutBytesRead
)
/*++

Routine Description:

    Description.

Arguments:

    BaseAddress - 
    Buffer - 
    BufferSize - 
    OutBytesRead - 

Return Value:

    None.

--*/
{
    HRESULT Result = S_FALSE;
    ULONG Index = 0;
    ULONG TotalBytesRead = 0;
    ULONG BytesRead = 0;
    ULONG BytesToRead;

    RtlZeroMemory(Buffer, BufferSize);

    for (Index = 0; TotalBytesRead < BufferSize; Index += 1) {

        BytesToRead = min(PAGE_SIZE, BufferSize - TotalBytesRead);

        Result = g_Ext->m_Data->ReadVirtual(BaseAddress + (Index * PAGE_SIZE),
                                            (PUCHAR)Buffer + (Index * PAGE_SIZE),
                                            BytesToRead,
                                            &BytesRead);
        if (Result != S_OK) {

            //
            // Check if base address is valid or not.
            //

            if (Index == 0) goto CleanUp;

            // g_Ext->Dml("Error: [%d] Can't read 0x%I64x bytes at %I64x.\n",
            //     Index, BytesToRead, BaseAddress + (Index * PAGE_SIZE));
            // goto CleanUp;
        }

        TotalBytesRead += BytesToRead;
    }

CleanUp:

    if (TotalBytesRead == BufferSize) Result = S_OK;

    if (OutBytesRead) *OutBytesRead = TotalBytesRead;

    return Result;
}

HRESULT
ExtRemoteTypedEx::ReadImageMemory(
    _In_ ULONG64 BaseAddress,
    _Out_writes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG OutBytesRead
    )
/*++

Routine Description:

    Description.

Arguments:

    BaseAddress - 
    Buffer - 
    BufferSize - 
    OutBytesRead - 

Return Value:

    None.

--*/
{
    HRESULT Result = S_FALSE;
    ULONG Index = 0;
    ULONG TotalBytesRead = 0;
    ULONG BytesRead = 0;
    ULONG BytesToRead;
    BOOL IsOk = TRUE;

    RtlZeroMemory(Buffer, BufferSize);

    for (Index = 0; TotalBytesRead < BufferSize; Index += 1) {

        BytesToRead = min(PAGE_SIZE, BufferSize - TotalBytesRead);

        Result = g_Ext->m_Data->ReadVirtual(BaseAddress + (Index * PAGE_SIZE),
                                            (PUCHAR)Buffer + (Index * PAGE_SIZE),
                                            BytesToRead,
                                            &BytesRead);
        if (Result != S_OK) {

            IsOk = FALSE;

            //
            // Check if base address is valid or not.
            //

            if (Index == 0) goto CleanUp;
        }

        TotalBytesRead += BytesToRead;
    }

CleanUp:

    if (TotalBytesRead == BufferSize) {

        Result = (IsOk == FALSE) ? E_ACCESSDENIED : S_OK;
    }

    if (OutBytesRead) *OutBytesRead = TotalBytesRead;

    return Result;
}

ULONG
ExtRemoteTypedEx::GetPointerSize(
)
/*++

Routine Description:

    Description.

Arguments:

     

Return Value:

    ULONG.

--*/
{
    ULONG PointerSize;

    if (g_Ext->m_Control->IsPointer64Bit() == S_OK) PointerSize = sizeof(ULONG64);
    else PointerSize = sizeof(ULONG32);

    return PointerSize;
}

ULONG64
ExtRemoteTypedEx::GetPointer(
    _In_ ULONG64 Address
)
/*++

Routine Description:

    Description.

Arguments:

    Address - 

Return Value:

    None.

--*/
{
    ULONG64 Pointer = 0;
    // ULONG BytesRead;
    // ULONG PointerSize;

    // if (g_Ext->m_Control->IsPointer64Bit() == S_OK) PointerSize = sizeof(ULONG64);
    // else PointerSize = sizeof(ULONG32);

    ReadPointer(Address, &Pointer);
    return Pointer;

    // g_Ext->m_Data->ReadVirtual(SIGN_EXTEND(Address), (PUCHAR)&Pointer, PointerSize, &BytesRead);
    // return SIGN_EXTEND(Pointer);
}

LPSTR
GetNameByOffset(
    _In_ ULONG64 Offset,
    _Out_writes_(NameSize) LPSTR Name,
    _In_ ULONG NameSize
)
/*++

Routine Description:

    Description.

Arguments:

    Offset - 
    Name - 
    NameSize - 

Return Value:

    LPSTR.

--*/
{
    HRESULT hResult;
    RtlZeroMemory(Name, NameSize);

    if (Offset)
    {
        // TODO: GetOffsetSymbol()
        hResult = g_Ext->m_Symbols->GetNameByOffset(Offset, (PSTR)Name, NameSize, NULL, NULL);
        if (hResult != S_OK)
        {
            strcpy_s((LPSTR)Name, NameSize, "*UNKNOWN*");
        }
    }

    return Name;
}

BOOLEAN
IsPointerHooked(
    _In_ ULONG64 Ptr
)
/*++

Routine Description:

    Description.

Arguments:

    Ptr - 

Return Value:

    BOOLEAN.

--*/
{
    UCHAR ByteCode[0x20] = { 0 };
    BOOLEAN Hooked = FALSE;

    if (g_Ext->m_Data->ReadVirtual(Ptr, ByteCode, sizeof(ByteCode), NULL) != S_OK) goto CleanUp;

    if (ByteCode[0] == 0xe9) // jmp
    {
        Hooked = TRUE;
        goto CleanUp;
    }
    else if (ByteCode[0] == 0xe8) // call
    {
        Hooked = TRUE;
        goto CleanUp;
    }
    else if ((ByteCode[0] == 0xb8) && // mov eax, XXXXXXXX
        (ByteCode[5] == 0xba) && // mov edx, XXXXXXXX
        (ByteCode[0xa] == 0xff) && (ByteCode[0xb] == 0x12) && // call [edx]
        (ByteCode[0xc] == 0xc2)) // retn
    {
        // NT Syscall
        ULONG Edx = ByteCode[6] | (ByteCode[7] << 8) | (ByteCode[8] << 16) | (ByteCode[9] << 24);
        if (Edx != 0x7ffe0300)
        {
            Hooked = TRUE;
            goto CleanUp;
        }
    }
    else if ((ByteCode[0] == 0x68) && // push XXXXXXX
        (ByteCode[5] == 0xc3)) // ret
    {
        Hooked = TRUE;
        goto CleanUp;
    }
    else if ((ByteCode[0] == 0xff) && (ByteCode[1] == 0x25)) // jmp dword ptr [XXXXXXXX]
    {
        Hooked = TRUE;
        goto CleanUp;
    }
    else if ((ByteCode[0] == 0xff) && (ByteCode[1] == 0x15)) // call dword ptr [XXXXXXXX]
    {
        Hooked = TRUE;
        goto CleanUp;
    }

CleanUp:
    return Hooked;
}


ULONG64
GetFastRefPointer(
    _In_ ULONG64 Pointer
)
/*++

Routine Description:

    Description.

Arguments:

    Pointer - 

Return Value:

    ULONG64.

--*/
{
    ULONG64 ExRefMask = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? ~0xF : ~0x7;

    Pointer &= ExRefMask;

    return (Pointer & ExRefMask);
}

ULONG
ReadPointersVirtual(
    _In_ ULONG PointerCount,
    _In_ ULONG64 Pointer,
    _Deref_out_range_(0, PointerCount) PULONG64 OutPtrTable
)
/*++

Routine Description:

    Description.

Arguments:

    PointerCount - 
    Pointer - 
    OutPtrTable -

Return Value:

    ULONG.

--*/
{
    ULONG i;
    ULONG Result = TRUE;

    for (i = 0; i < PointerCount; i += 1)
    {
        Result = ReadPointer(Pointer + (i * g_Ext->m_PtrSize), &OutPtrTable[i]);
        if (!Result) goto Exit;
    }

Exit:
    if (Result) Result = S_OK;
    else Result = S_FALSE;

    return Result;
}
