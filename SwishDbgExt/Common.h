/*++
    Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2014 MoonSols Ltd.
    Copyright (C) 2016 Comae Technologies FZE
    Copyright (C) 2014-2016 Matthieu Suiche (@msuiche)

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

    - Common.h

Abstract:


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/


#pragma once


#define BUFFER_SIZE 64 * 1024

#define MD5_HASH_LENGTH       16
#define SHA256_HASH_LENGTH    32


PSTR
GetISO8601Date(
    _In_ PSTR Buffer,
    _In_ ULONG Length,
    _In_ PFILETIME FileTime
    );

ULONGLONG
GetTimeStamp(
    VOID
    );

PSTR
GetArchitectureType(
    VOID
    );

PSTR
GetDumpType(
    _In_ ULONG Class,
    _In_ ULONG Qualifier
    );

PSTR
GetTargetName(
    _In_ PSTR Buffer,
    _In_ ULONG Length
    );

PSTR
GetIpAddressString(
    _In_ PSTR Buffer,
    _In_ ULONG Length,
    _In_ PBYTE Address,
    _In_ ULONG SizeOfAddress
    );

PSTR
GetGuidString(
    _In_ PSTR Buffer,
    _In_ ULONG Length,
    _In_ GUID *Guid
    );

PSTR
GetHashString(
    _Out_writes_(Length) PSTR Buffer,
    _In_ ULONG Length,
    _In_ PBYTE Hash,
    _In_ ULONG HashLength
    );

_Check_return_
BOOL
GetFileSize(
    _In_ PTSTR FileName,
    _Out_ PLARGE_INTEGER FileSize
    );

_Check_return_
BOOL
GetFileHash(
    _In_ PTSTR Buffer,
    _In_ ULONG Length,
    _In_ PTSTR FileName,
    _In_ DWORD ProviderType,
    _In_ ALG_ID AlgId
    );
