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

    - DbgHelpEx.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

    --*/

#include "MoonSolsDbgExt.h"

//
// PE functions
//

PVOID
PEFile::RtlGetRessourceData(
    ULONG Name,
    ULONG Type
)
/*++

Routine Description:

    Description.

Arguments:

    - Name
    - Type

Return Value:

    PVOID.

--*/
{
    PIMAGE_RESOURCE_DIRECTORY ImgResDir = NULL;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY ImgResDirEntry;
    PIMAGE_RESOURCE_DATA_ENTRY ImgResDataEntry;

    ULONG ResRva, ResSize;

    ULONG Index;

    PVOID RessourceData = NULL;
    ExtRemoteTyped BaseImage;

    //
    // Points to Data Directory Table.
    //
    ResRva = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    ResSize = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;

    //
    // Category.Type
    //
    ImgResDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)m_Image.Image + ResRva);
    ImgResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ImgResDir + 1);

    if (ImgResDir->NumberOfIdEntries > 26) ImgResDir->NumberOfIdEntries = 26;

    for (Index = 0; Index < ImgResDir->NumberOfIdEntries; Index += 1)
    {
        if (ImgResDirEntry[Index].Name == Type) break;
    }

    if ((Index == ImgResDir->NumberOfIdEntries) || (!ImgResDirEntry[Index].DataIsDirectory)) goto CleanUp;

    //
    // Sub-category.Name
    //
    ImgResDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)m_Image.Image + ResRva + ImgResDirEntry[Index].OffsetToDirectory);
    ImgResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ImgResDir + 1);

    if (ImgResDir->NumberOfIdEntries > 26) ImgResDir->NumberOfIdEntries = 26;

    for (Index = 0; Index < ImgResDir->NumberOfIdEntries; Index += 1)
    {
        if (ImgResDirEntry[Index].Name == Name) break;
    }

    if ((Index == ImgResDir->NumberOfIdEntries) || (!ImgResDirEntry[Index].DataIsDirectory)) goto CleanUp;

    //
    // Read first entry by default.
    //
    ImgResDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)m_Image.Image + ResRva + ImgResDirEntry[Index].OffsetToDirectory);
    ImgResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ImgResDir + 1);

    if (ImgResDirEntry[0].DataIsDirectory) goto CleanUp;

    ImgResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((PUCHAR)m_Image.Image + ResRva + ImgResDirEntry[0].OffsetToDirectory);
    RessourceData = malloc(ImgResDataEntry->Size);
    if (RessourceData == NULL) goto CleanUp;

    memcpy_s(RessourceData, ImgResDataEntry->Size, (PUCHAR)m_Image.Image + ImgResDataEntry->OffsetToData, ImgResDataEntry->Size);

CleanUp:
    return RessourceData;
}

BOOLEAN
PEFile::RtlGetPdbInfo(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    BOOLEAN.

--*/
{
    BOOLEAN Result = FALSE;
    PIMAGE_DEBUG_DIRECTORY DbgDir = NULL;
    ULONG Offset;

    if (!m_Image.Initialized) goto CleanUp;

    Offset = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
    if (!Offset || (m_ImageSize && (Offset > m_ImageSize))) goto CleanUp;
    DbgDir = (PIMAGE_DEBUG_DIRECTORY)(((PUCHAR)m_Image.Image) + Offset);

    Offset = DbgDir->AddressOfRawData;
    if (!Offset || (m_ImageSize && (Offset > m_ImageSize))) goto CleanUp;
    PCV_INFO_PDB70 PdbInfo = (PCV_INFO_PDB70)(((PUCHAR)m_Image.Image) + Offset);;

    if (PdbInfo->Signature == CV_SIGNATURE_RSDS)
    {
        m_PdbInfo.Guid = PdbInfo->Guid;
        m_PdbInfo.Age = PdbInfo->Age;

        strcpy_s(m_PdbInfo.PdbName, sizeof(m_PdbInfo.PdbName), PdbInfo->PdbFileName);
        Result = TRUE;
    }

CleanUp:
    return Result;
}

BOOLEAN
PEFile::RtlGetExports(
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    BOOLEAN.

--*/
{
    BOOLEAN Result = FALSE;
    PIMAGE_EXPORT_DIRECTORY ExportDir = NULL;

    ULONG DirRva, DirSize;

    PULONG AddressOfNames;
    PUSHORT AddressOfNameOrdinals;
    PULONG AddressOfFunctions;

    UINT i;

    ASSERTDBG(m_Image.Initialized);
    if (!m_Image.Initialized) goto CleanUp;

    DirRva = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DirSize = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (!DirRva || (m_ImageSize && (DirRva > m_ImageSize))) goto CleanUp;

    PUCHAR Image = ((PUCHAR)m_Image.Image);

    if (!DirSize || !DirRva) goto CleanUp;

    ExportDir = (PIMAGE_EXPORT_DIRECTORY)(Image + DirRva);

    if ((ExportDir->AddressOfNames >= (DirRva + DirSize)) ||
        (ExportDir->AddressOfNameOrdinals >= (DirRva + DirSize)) ||
        (ExportDir->AddressOfFunctions >= (DirRva + DirSize)))
    {
        goto CleanUp;
    }

    AddressOfNames = (PULONG)(Image + (ULONG)ExportDir->AddressOfNames);
    AddressOfNameOrdinals = (PUSHORT)(Image + (ULONG)ExportDir->AddressOfNameOrdinals);
    AddressOfFunctions = (PULONG)(Image + (ULONG)ExportDir->AddressOfFunctions);

#if VERBOSE_MODE
    g_Ext->Dml("(%s) ExportDir->NumberOfName: %d, ExportDir->NumberOfFunctions: %d\n",
               m_PdbInfo.PdbName, ExportDir->NumberOfNames, ExportDir->NumberOfFunctions);
#endif

    m_NumberOfExportedFunctions = ExportDir->NumberOfNames;
    ULONG NumberOfHookedAPIs = 0;
    for (i = 0; i < ExportDir->NumberOfNames && i < 5000; i += 1)
    {
        EXPORT_INFO ExportInfo = { 0 };

        if (AddressOfNameOrdinals[i] >= ExportDir->NumberOfNames) continue;

        ExportInfo.Address = AddressOfFunctions[AddressOfNameOrdinals[i]];

        ExportInfo.Index = i;
        ExportInfo.Ordinal = AddressOfNameOrdinals[i];
        ExportInfo.IsTablePatched = (ExportInfo.Address >= m_ImageSize) ? TRUE : FALSE;
        ExportInfo.IsHooked = IsPointerHooked(m_ImageBase + ExportInfo.Address);
        if (ExportInfo.IsTablePatched || ExportInfo.IsHooked) NumberOfHookedAPIs++;

        ULONG Len = (ULONG)strnlen_s((LPSTR)(Image + AddressOfNames[i]), sizeof(ExportInfo.Name) - 1);
        if ((AddressOfNames[i] <= (DirRva + DirSize)) && Len)
        {
            // strcpy_s(ExportInfo.Name, sizeof(ExportInfo.Name), (LPSTR)(Image + AddressOfNames[i]));
            memcpy_s(ExportInfo.Name, sizeof(ExportInfo.Name), (LPSTR)(Image + AddressOfNames[i]), Len);
        }
        else
        {
            strcpy_s(ExportInfo.Name, sizeof(ExportInfo.Name), "*unreadable*");
        }

        m_Exports.push_back(ExportInfo);
    }

    m_NumberOfHookedAPIs = NumberOfHookedAPIs;

    Result = TRUE;

CleanUp:
    return Result;
}

BOOLEAN
PEFile::RtlGetFileVersion(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    BOOLEAN.

--*/
{
    PVOID RessourceData = NULL;

    UINT TranslateSize;
    WCHAR MagicLine[MAX_PATH + 1];
    PVOID Description;
    UINT DescriptionSize;

    PLANGANDCODEPAGE Translation;

    BOOLEAN Result = TRUE;

    RessourceData = RtlGetRessourceData(VS_VERSION_INFO, (ULONG)RT_VERSION);
    // ASSERTDBG(RessourceData);
    if (RessourceData == NULL) goto CleanUp;

    // Read the list of languages and code pages.

    Result = VerQueryValueW(RessourceData,
        L"\\VarFileInfo\\Translation",
        (LPVOID*)&Translation,
        &TranslateSize);

    if (!Result || Translation == NULL) goto CleanUp;

    //
    // Product Version
    //
    swprintf_s(MagicLine, sizeof(MagicLine),
        L"\\StringFileInfo\\%04x%04x\\ProductVersion",
        Translation[0].wLanguage,
        Translation[0].wCodePage);

    VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);
    if (DescriptionSize)
    {
        swprintf_s(m_FileVersion.ProductVersion, sizeof(m_FileVersion.ProductVersion),
            L"%s", Description);
    }

    //
    // File Version
    //
    swprintf_s(MagicLine, sizeof(MagicLine),
        L"\\StringFileInfo\\%04x%04x\\FileVersion",
        Translation[0].wLanguage,
        Translation[0].wCodePage);

    VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);
    if (DescriptionSize)
    {
        swprintf_s(m_FileVersion.FileVersion, sizeof(m_FileVersion.FileVersion),
            L"%s", Description);
    }

    //
    // Company Name
    //
    swprintf_s(MagicLine, sizeof(MagicLine),
        L"\\StringFileInfo\\%04x%04x\\CompanyName",
        Translation[0].wLanguage,
        Translation[0].wCodePage);

    VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);
    if (DescriptionSize)
    {
        swprintf_s(m_FileVersion.CompanyName, sizeof(m_FileVersion.CompanyName),
            L"%s", Description);
    }

    //
    // File Description
    //
    swprintf_s(MagicLine, sizeof(MagicLine),
        L"\\StringFileInfo\\%04x%04x\\FileDescription",
        Translation[0].wLanguage,
        Translation[0].wCodePage);

    VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);
    if (DescriptionSize)
    {
        swprintf_s(m_FileVersion.FileDescription, sizeof(m_FileVersion.FileDescription),
            L"%s", Description);
    }

#if VERBOSE_MODE
    // g_Ext->Dml("FileDesc: %S\n", ProcessObject.m_CcProcessObject.FileDescription);
#endif

    Result = TRUE;

CleanUp:

    if (RessourceData) free(RessourceData);
    return Result;
}

BOOLEAN
PEFile::RtlGetSections(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    BOOLEAN.

--*/
{
    ULONG Index;

    for (Index = 0; Index < m_Image.NumberOfSections; Index += 1)
    {
        CACHED_SECTION_INFO SectionInfo = { 0 };
        MD5_CONTEXT Md5Context = { 0 };

        memcpy_s(SectionInfo.Name, sizeof(SectionInfo.Name),
            m_Image.Sections[Index].Name, sizeof(m_Image.Sections[Index].Name));
        SectionInfo.VaBase = m_Image.Sections[Index].VirtualAddress;
        SectionInfo.VaSize = m_Image.Sections[Index].Misc.VirtualSize;
        SectionInfo.RawSize = m_Image.Sections[Index].SizeOfRawData;

        if (SectionInfo.VaSize > m_ImageSize) continue;

        if (g_Verbose) g_Ext->Dml("[%d][%s] Base = 0x%I64X Size = 0x%x RawSize = 0x%x\n", Index, SectionInfo.Name, SectionInfo.VaBase, SectionInfo.VaSize, SectionInfo.RawSize);

        MD5Init(&Md5Context);
        MD5Update(&Md5Context, (PUCHAR)m_Image.Image + SectionInfo.VaBase, SectionInfo.RawSize);
        MD5Final(&Md5Context);

        memcpy_s(SectionInfo.VaMd5Hash, sizeof(SectionInfo.VaMd5Hash), Md5Context.Digest, sizeof(Md5Context.Digest));

#if VERBOSE_MODE
        g_Ext->Dml("Section: %s\n", SectionInfo.Name);
        g_Ext->Dml("Md5: ");
        for (UINT i = 0; i < 16; i++) g_Ext->Dml("%02x", Md5Context.Digest[i]);
        g_Ext->Dml("\n");
#endif

        // VirusTotal::GetReport(Md5Context.Digest);

        m_CcSections.push_back(SectionInfo);
    }

    return TRUE;
}

BOOLEAN
PEFile::InitImage(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    BOOLEAN.

--*/
{
    PIMAGE_DOS_HEADER Header = NULL;
    PVOID Image = NULL;
    ULONG BytesRead = 0;
    ULONG64 BaseImageAddress = m_ImageBase;

    PIMAGE_NT_HEADERS32 NtHeader32 = NULL;
    PIMAGE_NT_HEADERS64 NtHeader64 = NULL;

    PIMAGE_DATA_DIRECTORY DataDirectory = NULL;
    ExtRemoteTyped BaseImage;

    BOOLEAN Result = FALSE;
    ULONG64 ProcessDataOffset = 0ULL;

    if (m_Image.Initialized)
    {
        // g_Ext->Dml("b_Initialized already set to TRUE\n");
        Result = TRUE;
        goto CleanUp;
    }

    if (!m_ImageSize)
    {
        Header = (PIMAGE_DOS_HEADER)malloc(PAGE_SIZE);
        if (Header == NULL) goto CleanUp;
        RtlZeroMemory(Header, PAGE_SIZE);

        if (g_Ext->m_Data->ReadVirtual(BaseImageAddress, Header, PAGE_SIZE, &BytesRead) != S_OK)
        {
#if VERBOSE_MODE
            g_Ext->Dml("Error: Can't read 0x%I64x bytes at %I64x.\n", PAGE_SIZE, BaseImageAddress);
#endif
            goto CleanUp;
        }

        BaseImage = ExtRemoteTyped("(nt!_IMAGE_DOS_HEADER *)@$extin", BaseImageAddress);
        if (BaseImage.Field("e_magic").GetUshort() != IMAGE_DOS_SIGNATURE) goto CleanUp;

        NtHeader32 = (PIMAGE_NT_HEADERS32)((PUCHAR)Header + BaseImage.Field("e_lfanew").GetUlong());

        if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            m_ImageSize = NtHeader32->OptionalHeader.SizeOfImage;
        }
        else if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader32;
            NtHeader32 = NULL;
            m_ImageSize = NtHeader64->OptionalHeader.SizeOfImage;;
        }
        else
        {
#if VERBOSE_MODE
            g_Ext->Dml("Error: Invalid signature.\n");
#endif
            goto CleanUp;
        }
    }

    Image = malloc(m_ImageSize);
    if (Image == NULL) goto CleanUp;
    RtlZeroMemory(Image, (ULONG)m_ImageSize);

    if (ExtRemoteTypedEx::ReadVirtual(BaseImageAddress, Image, (ULONG)m_ImageSize, &BytesRead) != S_OK)
    {
#if VERBOSE_MODE
        g_Ext->Dml("Error: Can't read 0x%I64x bytes at %I64x.\n", m_ImageSize, BaseImageAddress);
#endif
        goto CleanUp;
    }

    m_Image.Image = (PIMAGE_DOS_HEADER)Image;
    REF_POINTER(m_Image.Image);

    m_Image.NtHeader32 = (PIMAGE_NT_HEADERS32)((PUCHAR)Image + m_Image.Image->e_lfanew);
    NtHeader32 = m_Image.NtHeader32;

    if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        m_Image.NtHeader32 = NULL;
        m_Image.NtHeader64 = (PIMAGE_NT_HEADERS64)((PUCHAR)Image + m_Image.Image->e_lfanew);
        m_Image.DataDirectory = (PIMAGE_DATA_DIRECTORY)m_Image.NtHeader64->OptionalHeader.DataDirectory;
        m_Image.Sections = (PIMAGE_SECTION_HEADER)(m_Image.NtHeader64 + 1);

        m_Image.NumberOfSections = m_Image.NtHeader64->FileHeader.NumberOfSections;
    }
    else if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        m_Image.NtHeader64 = NULL;
        m_Image.DataDirectory = (PIMAGE_DATA_DIRECTORY)m_Image.NtHeader32->OptionalHeader.DataDirectory;
        m_Image.Sections = (PIMAGE_SECTION_HEADER)(m_Image.NtHeader32 + 1);
        m_Image.NumberOfSections = m_Image.NtHeader32->FileHeader.NumberOfSections;
    }
    else
    {
        goto CleanUp;
    }

#if VERBOSE_MODE
    g_Ext->Dml("m_Image = %p\n"
        "m_NtHeader32 = %p\n"
        "m_DataDirectory = %p\n"
        "m_Sections = %p\n", m_Image.Image, m_Image.NtHeader32, m_Image.DataDirectory, m_Image.Sections);

    g_Ext->Dml("m_NumberOfSections = %x\n", m_Image.NumberOfSections);
#endif

    Result = TRUE;

CleanUp:
    if (Header) free(Header);

    m_Image.Initialized = Result;

    return Result;
}

BOOLEAN
PEFile::GetInfoFull(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    BOOLEAN.

--*/
{
    BOOLEAN Result = FALSE;

    Result = InitImage();
    if (Result == FALSE) goto CleanUp;

    RtlGetFileVersion();
    // if (Result == FALSE) goto CleanUp;

    RtlGetPdbInfo();

    RtlGetSections();
    //if (Result == FALSE) goto CleanUp;

    //
    // Dlls
    //
    // ExtNtOsInformation::GetUserLoadedModuleListHead(_In_ bool NativeOnly)
    // ExtNtOsInformation::GetUserLoadedModuleList(_In_ bool NativeOnly)

    Result = TRUE;

CleanUp:
    return Result;
}
