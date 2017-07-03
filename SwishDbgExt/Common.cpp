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
GetDumpType(
    _In_ ULONG Class,
    _In_ ULONG Qualifier
    )
{
    if (Class == DEBUG_CLASS_KERNEL) {

        switch (Qualifier) {

        case DEBUG_KERNEL_CONNECTION:  return "Kernel Connection";
        case DEBUG_KERNEL_LOCAL:       return "Kernel Local";
        case DEBUG_KERNEL_EXDI_DRIVER: return "Kernel EXDI Driver";
        case DEBUG_KERNEL_SMALL_DUMP:  return "Kernel Small Dump";
        case DEBUG_KERNEL_DUMP:        return "Kernel Dump";
        case DEBUG_KERNEL_FULL_DUMP:   return "Kernel Full Dump";
        default:                       return "";
        }
    }

    return "";
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
GetIpAddressString(
    _In_ PSTR Buffer,
    _In_ ULONG Length,
    _In_ PBYTE Address,
    _In_ ULONG SizeOfAddress
    )
{
    Buffer[0] = '\0';

    if (SizeOfAddress == sizeof(IN_ADDR)) {

        StringCchPrintf(Buffer,
                        Length,
                        "%d.%d.%d.%d",
                        Address[0],
                        Address[1],
                        Address[2],
                        Address[3]);
    }
    else {

        StringCchPrintf(Buffer,
                        Length,
                        "%x:%x:%x:%x:%x:%x:%x:%x",
                        _byteswap_ushort(((PUSHORT)Address)[0]),
                        _byteswap_ushort(((PUSHORT)Address)[1]),
                        _byteswap_ushort(((PUSHORT)Address)[2]),
                        _byteswap_ushort(((PUSHORT)Address)[3]),
                        _byteswap_ushort(((PUSHORT)Address)[4]),
                        _byteswap_ushort(((PUSHORT)Address)[5]),
                        _byteswap_ushort(((PUSHORT)Address)[6]),
                        _byteswap_ushort(((PUSHORT)Address)[7]));
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
GetHashString(
    _Out_writes_(Length) PSTR Buffer,
    _In_ ULONG Length,
    _In_ PBYTE Hash,
    _In_ ULONG HashLength
    )
{
    Buffer[0] = '\0';

    CryptBinaryToStringA(Hash, HashLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, Buffer, &Length);

    return Buffer;
}

_Check_return_
BOOL
GetFileSize(
    _In_ PTSTR FileName,
    _Out_ PLARGE_INTEGER FileSize
    )
{
    BOOL IsOk = FALSE;
    HANDLE hFile;
    OFSTRUCT of;

    hFile = (HANDLE)(ULONG_PTR)OpenFile(FileName, &of, OF_READ);

    if (hFile) {

        if (GetFileSizeEx(hFile, FileSize)) {

            IsOk = TRUE;
        }

        CloseHandle(hFile);
    }

    return IsOk;
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
    PBYTE Hash;
    DWORD HashLength;
    DWORD NumberOfBytesRead;
    BOOL Status = FALSE;

    Buffer[0] = '\0';

    if (0 == _tfopen_s(&File, FileName, "rb")) {

        if (GetFileSize(FileName, &FileSize)) {

            Data = (PBYTE)calloc(BUFFER_SIZE, sizeof(BYTE));

            if (Data) {

                if (CryptAcquireContext(&hCryptProvider, NULL, NULL, ProviderType, CRYPT_VERIFYCONTEXT)) {

                    if (CryptCreateHash(hCryptProvider, AlgId, NULL, 0, &hHash)) {

                        while ((NumberOfBytesRead = (DWORD)fread(Data, sizeof(BYTE), BUFFER_SIZE, File)) != 0) {

                            TotalNumberOfBytesRead += NumberOfBytesRead;

                            if (!CryptHashData(hHash, (PBYTE)Data, NumberOfBytesRead, 0)) {

                                break;
                            }
                        }

                        if (TotalNumberOfBytesRead == FileSize.QuadPart) {

                            if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, &HashLength, 0)) {

                                Hash = (PBYTE)calloc(HashLength, sizeof(BYTE));

                                if (Hash) {

                                    if (CryptGetHashParam(hHash, HP_HASHVAL, Hash, &HashLength, 0)) {

                                        if (CryptBinaryToString(Hash, HashLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, Buffer, &Length)) {

                                            Status = TRUE;
                                        }
                                    }

                                    free(Hash);
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
