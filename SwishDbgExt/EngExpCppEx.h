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

    - EngExtCppEx.h

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

BOOLEAN
IsValid(
    ULONG64 Pointer
);

LPSTR
GetNameByOffset(
    ULONG64 Offset,
    LPSTR Name,
    ULONG NameSize
);

BOOLEAN
IsPointerHooked(
ULONG64 Ptr
);


ULONG64
GetFastRefPointer(
ULONG64 Pointer
);

ULONG
ReadPointersVirtual(
ULONG PointerCount,
ULONG64 Pointer,
PULONG64 OutPtrTable
);

class ExtRemoteTypedEx
{
public:
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaxLength;
        ULONG64 Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    static LPWSTR GetUnicodeString(
        ExtRemoteTyped TypedObject,
        _Out_writes_opt_(BufferChars) PWSTR Buffer,
        _In_ ULONG MaxChars
    );

    static LPWSTR
        ExtRemoteTypedEx::GetUnicodeString2(
        ExtRemoteTyped TypedObject
    );

    static LPWSTR
        GetUnicodeStringEx(
        ULONG64 UntypedObject,
        _Out_writes_opt_(BufferChars) PWSTR Buffer,
        _In_ ULONG MaxChars
    );

    static LPWSTR ExtRemoteTypedEx::GetString(
        ULONG64 Address,
        _Out_writes_opt_(BufferChars) LPWSTR Buffer,
        _In_ ULONG MaxChars
    );

    static ULONG64 GetPointer(
        ULONG64 Address
    );

    static ULONG GetPointerSize(
    );

    static HRESULT ReadVirtual(
        ULONG64 BaseAddress,
        PVOID Buffer,
        ULONG BufferSize,
       _Out_ PULONG OutBytesRead
    );

    static
    HRESULT
    ReadImageMemory(
        _In_ ULONG64 BaseAddress,
        _Out_writes_(BufferSize) PVOID Buffer,
        _In_ ULONG BufferSize,
        _Out_opt_ PULONG OutBytesRead
        );

private:
};