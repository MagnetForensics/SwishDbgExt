/*++
    MoonSols Incident Response & Digital Forensics Debugging Extension

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

    - DbgHelpEx.h

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "MoonSolsDbgExt.h"

#ifndef __DBGHELPEX_H__
#define __DBGHELPEX_H__

#define CV_SIGNATURE_RSDS 'SDSR'

typedef struct _CV_INFO_PDB70
{
    DWORD Signature;
    GUID Guid; // unique identifier 
    DWORD Age; // an always-incrementing value 
    CHAR PdbFileName[1]; // zero terminated string with the name of the PDB file 
} CV_INFO_PDB70, *PCV_INFO_PDB70;

class PEFile {
public:
    typedef enum _IMAGE_TYPE {
        ImageInvalidType = 0,
        ImageProcessType = 1,
        ImageDllType = 2,
        ImageModuleType = 3
    } IMAGE_TYPE, *PIMAGE_TYPE;

    typedef struct _IMAGE_DATA {
        PIMAGE_DOS_HEADER Image;
        PIMAGE_NT_HEADERS32 NtHeader32;
        PIMAGE_NT_HEADERS64 NtHeader64;
        PIMAGE_DATA_DIRECTORY DataDirectory;
        PIMAGE_SECTION_HEADER Sections;

        ULONG NumberOfSections;

        BOOLEAN Initialized;
    } IMAGE_DATA, *PIMAGE_DATA;

    typedef struct _CACHED_SECTION_INFO {
        ULONG Index;

        UCHAR Name[9];

        ULONG VaBase;
        ULONG VaSize;
        CHAR VaMd5Hash[16];

        ULONG RawBase;
        ULONG RawSize;
        CHAR RawMd5Hash[16];

        BOOLEAN IsExecutable;
        ULONG32 Characteristics;
    } CACHED_SECTION_INFO, *PCACHED_SECTION_INFO;

    typedef struct _PDB_INFO {
        GUID Guid;
        ULONG Age;
        CHAR PdbName[MAX_PATH + 1];
    } PDB_INFO, *PPDB_INFO;

    typedef struct _LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } LANGANDCODEPAGE, *PLANGANDCODEPAGE;

    typedef struct _FILE_VERSION {
        WCHAR ProductVersion[256];
        WCHAR FileVersion[256];
        WCHAR CompanyName[256];
        WCHAR FileDescription[256];
    } FILE_VERSION, *PFILE_VERSION;

    typedef struct _EXPORT_INFO {
        ULONG Index;
        ULONG64 Address;
        ULONG Ordinal;
        CHAR Name[128];

        BOOL IsTablePatched;
        BOOL IsHooked;
    } EXPORT_INFO, *PEXPORT_INFO;

    ULONG64 m_ImageBase;
    ULONG m_ImageSize;

    vector<CACHED_SECTION_INFO> m_CcSections;
    FILE_VERSION m_FileVersion;
    IMAGE_DATA m_Image;
    PDB_INFO m_PdbInfo;

    ULONG64 m_ObjectPtr;

    //
    // Exports
    //
    vector<EXPORT_INFO> m_Exports;
    ULONG m_NumberOfHookedAPIs;
    ULONG m_NumberOfExportedFunctions;

    PVOID
    RtlGetRessourceData(
       _In_ ULONG Name,
       _In_ ULONG Type
    );

    BOOLEAN
    RtlGetExports(
    );

    BOOLEAN
    InitImage(
    );

    BOOLEAN
    RtlGetSections(
    );

    BOOLEAN
    RtlGetFileVersion(
    );

    BOOLEAN
    RtlGetPdbInfo(
    );

    BOOLEAN
    GetInfoFull(
    );

    void Free(void);

protected:
    void Clear(void)
    {
        Free();

        m_Image.Initialized = FALSE;
        m_ImageSize = 0;
        m_ImageBase = 0ULL;
    }
};

#endif