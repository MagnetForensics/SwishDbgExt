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

    - Common.cpp

Abstract:


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"

PSTR
GetISO8601Date(
    _In_ PSTR Buffer,
    _In_ ULONG Length,
    _In_ PFILETIME FileTime
    )
{
    SYSTEMTIME SystemTime;

    Buffer[0] = '\0';

    if ((FileTime->dwHighDateTime || FileTime->dwLowDateTime) && FileTimeToSystemTime(FileTime, &SystemTime)) {

        StringCchPrintfA(Buffer,
                         Length,
                         "%i-%02i-%02iT%02i:%02i:%02i.%03iZ",
                         SystemTime.wYear,
                         SystemTime.wMonth,
                         SystemTime.wDay,
                         SystemTime.wHour,
                         SystemTime.wMinute,
                         SystemTime.wSecond,
                         SystemTime.wMilliseconds);
    }

    return Buffer;
}

ULONGLONG
GetTimeStamp(
    VOID
    )
{
    FILETIME ft = {0};
    LARGE_INTEGER li = {0};

    GetSystemTimeAsFileTime(&ft);

    li.HighPart = ft.dwHighDateTime;
    li.LowPart = ft.dwLowDateTime;

    return li.QuadPart;
}

PSTR
GetArchitectureType(
    VOID
    )
{
    switch (g_Ext->m_ActualMachine) {

    case IMAGE_FILE_MACHINE_I386:  return "x86";
    case IMAGE_FILE_MACHINE_AMD64: return "x64";
    default:                       return "Unknown";
    }
}

PSTR
GetTargetName(
    _In_ PSTR Buffer,
    _In_ ULONG Length
    )
{
    ULONG64 Address;
    WCHAR UnicodeString[MAX_PATH];

    if ((g_Ext->m_Symbols->GetOffsetByName("srv!SrvComputerName", &Address) == S_OK)) {

        ExtRemoteTypedEx::GetUnicodeStringEx(Address, UnicodeString, sizeof(UnicodeString));

        StringCchPrintf(Buffer, Length, "%S", UnicodeString);
    }

    return Buffer;
}

PSTR
GetGuidString(
    _In_ PSTR Buffer,
    _In_ ULONG Length,
    _In_ GUID *Guid
    )
{
    Buffer[0] = '\0';

    StringCchPrintfA(Buffer,
                     Length,
                     "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
                     Guid->Data1,
                     Guid->Data2,
                     Guid->Data3,
                     Guid->Data4[0],
                     Guid->Data4[1],
                     Guid->Data4[2],
                     Guid->Data4[3],
                     Guid->Data4[4],
                     Guid->Data4[5],
                     Guid->Data4[6],
                     Guid->Data4[7]);

    return Buffer;
}

PSTR
GetMd5HashString(
    _In_ PSTR Buffer,
    _In_ ULONG Length,
    _In_ PBYTE Hash
    )
{
    Buffer[0] = '\0';

    StringCchPrintfA(Buffer,
                    Length,
                    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    Hash[0], Hash[1], Hash[2], Hash[3], Hash[4], Hash[5], Hash[6], Hash[7],
                    Hash[8], Hash[9], Hash[10], Hash[11], Hash[12], Hash[13], Hash[14], Hash[15]);

    return Buffer;
}

_Check_return_
BOOL
GetFileSize(
    _In_ PTSTR FileName,
    _Out_ PLARGE_INTEGER FileSize
    )
{
    WIN32_FILE_ATTRIBUTE_DATA FileAttributeData;

    if (GetFileAttributesEx(FileName, GetFileExInfoStandard, &FileAttributeData)) {

        FileSize->LowPart = FileAttributeData.nFileSizeLow;
        FileSize->HighPart = FileAttributeData.nFileSizeHigh;

        return TRUE;
    }

    return FALSE;
}

_Check_return_
BOOL
GetFileHash(
    _In_ PTSTR Buffer,
    _In_ ULONG Length,
    _In_ PTSTR FileName,
    _In_ DWORD ProviderType,
    _In_ ALG_ID AlgId
    )
{
    HCRYPTPROV hCryptProvider;
    HCRYPTHASH hHash;
    LARGE_INTEGER FileSize;
    LONGLONG TotalNumberOfBytesRead = 0;
    FILE *File;
    PBYTE Data;
    DWORD DataLength;
    DWORD NumberOfBytesRead;
    BOOL Status = FALSE;

    Buffer[0] = '\0';

    if (0 == _tfopen_s(&File, FileName, "rb")) {

        if (GetFileSize(FileName, &FileSize)) {

            Data = (PBYTE)calloc(BUFFER_SIZE, sizeof(BYTE));

            if (Data) {

                if (CryptAcquireContext(&hCryptProvider, NULL, NULL, ProviderType, 0)) {

                    if (CryptCreateHash(hCryptProvider, AlgId, NULL, 0, &hHash)) {

                        while ((NumberOfBytesRead = (DWORD)fread(Data, sizeof(BYTE), BUFFER_SIZE, File)) != 0) {

                            TotalNumberOfBytesRead += NumberOfBytesRead;

                            if (!CryptHashData(hHash, (PBYTE)Data, NumberOfBytesRead, 0)) {

                                break;
                            }
                        }

                        if (TotalNumberOfBytesRead == FileSize.QuadPart) {

                            if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, &DataLength, 0)) {

                                if (CryptGetHashParam(hHash, HP_HASHVAL, Data, &DataLength, 0)) {

                                    if (CryptBinaryToString(Data, DataLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, Buffer, &Length)) {

                                        Status = TRUE;
                                    }
                                }
                            }
                        }

                        CryptDestroyHash(hHash);
                    }

                    CryptReleaseContext(hCryptProvider, 0);
                }

                free(Data);
            }
        }

        fclose(File);
    }

    return Status;
}
