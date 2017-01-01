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

    - UntypedData.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx
    - TODO: set symbols noisy

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef __UNTYPED_DATA_H__
#define __UNTYPED_DATA_H__

class ExtRemoteUnTyped : public ExtRemoteData {
public:
    typedef struct _TYPED_DATA_FIELD {
        LPSTR FieldName;
        ULONG Offset;
        ULONG Size;
    } TYPED_DATA_FIELD, *PTYPED_DATA_FIELD;

    typedef struct _TYPED_DATA_VERSION {
        ULONG MachineType;
        ULONG MinorVersion;
        ULONG MajorVersion;
        ULONG ServicePack;

        ULONG TypeSize;
        PTYPED_DATA_FIELD Fields;
    } TYPED_DATA_VERSION, *PTYPED_DATA_VERSION;

    typedef struct _TYPED_DATA {
        LPSTR TypeName;
        PTYPED_DATA_VERSION Type;
    } TYPED_DATA, *PTYPED_DATA;

    ExtRemoteUnTyped(
    ) throw(...)
    {
    }

    ExtRemoteUnTyped(
        PCSTR TypeName
        )  throw(...)
    {
        Set(0, TypeName);
        // ExtRemoteData::Set(Ptr, m_TypedData->TypeSize);
    }

    ExtRemoteUnTyped(
        ULONG64 Ptr,
        PCSTR TypeName
    )  throw(...)
    {
        Set(Ptr, TypeName);
        ExtRemoteData::Set(Ptr, m_TypedData->TypeSize);
    }

    ExtRemoteUnTyped(
        ULONG64 Ptr,
        PCSTR TypeName,
        PCSTR Field,
        ULONG Size) throw(...)
    {
        Set(Ptr, TypeName); // We keep the same structure name. TODO: Links

        strcpy_s(m_Field, sizeof(m_Field), Field);
        m_FieldSize = Size;
        ExtRemoteData::Set(Ptr, Size);
    }

    ExtRemoteUnTyped operator[](_In_ LONG Index) throw(...)
    {
        return ArrayElement(Index);
    }
    ExtRemoteUnTyped operator[](_In_ ULONG Index) throw(...)
    {
        return ArrayElement((LONG64)Index);
    }
    ExtRemoteUnTyped operator[](_In_ LONG64 Index) throw(...)
    {
        return ArrayElement(Index);
    }
    ExtRemoteUnTyped operator[](_In_ ULONG64 Index) throw(...)
    {
        if (Index > 0x7fffffffffffffffUI64)
        {
            g_Ext->ThrowRemote
                (HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW),
                "Array index too large");
        }
        return ArrayElement((LONG64)Index);
    }

    VOID Set(ULONG64 Ptr, PCSTR TypeName) throw(...);

    ULONG64 GetPointerTo(void) throw(...);
    PTYPED_DATA_FIELD GetField(_In_ PCSTR Field) throw(...);
    BOOLEAN HasField(_In_ PCSTR Field) throw(...);
    ULONG GetFieldOffset(_In_ PCSTR Field) throw(...);
    VOID SubtractOffset(_In_ PCSTR Field) throw(...);
    ExtRemoteUnTyped Field(_In_ PCSTR Field) throw(...);
    ExtRemoteUnTyped Field(_In_ PCSTR Field, BOOLEAN IsPtr) throw(...);

    ExtRemoteUnTyped ArrayElement(_In_ LONG64 Index) throw(...);

    BOOLEAN m_Initialized;
    ULONG64 m_UntypedDataPtr;
    PTYPED_DATA_VERSION m_TypedData;

    CHAR m_TypeName[MAX_PATH];
    CHAR m_Field[MAX_PATH];
    ULONG m_FieldSize;
};

ULONG
GetUntypedTypeSize(
_In_ PCSTR TypeName
);

ULONG
GetFieldOffset(
_In_ PCSTR TypeName,
_In_ PCSTR Field
);

#endif