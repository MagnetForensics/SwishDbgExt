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

    - DbgHelpEx.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

    --*/

#include "stdafx.h"
#include "SwishDbgExt.h"

//
// PE functions
//


BOOL
MsPEImageFile::IsValidAddress(
    _In_ ULONG_PTR Address
    )
{
    ULONG_PTR ImageBase = (ULONG_PTR)m_Image.Image;

    if (Address >= ImageBase && Address < (ImageBase + m_ImageSize)) {

        return TRUE;
    }

    return FALSE;
}

VOID
MsPEImageFile::GetAddressInfo(
    _In_ ULONG64 Address,
    _Out_ PADDRESS_INFO AddressInfo
    )
{
    AddressInfo->Address = Address;
    AddressInfo->HookType = GetPointerHookType(Address);

    if (Address && m_ImageBase && m_ImageSize) {

        AddressInfo->IsTablePatched = (Address >= m_ImageBase && Address < (m_ImageBase + m_ImageSize)) ? FALSE : TRUE;
    }
}

PVOID
MsPEImageFile::RtlGetRessourceData(
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
    PIMAGE_RESOURCE_DIRECTORY ImgResDir;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY ImgResDirEntry;
    PIMAGE_RESOURCE_DATA_ENTRY ImgResDataEntry;
    PVOID RessourceData = NULL;
    ExtRemoteTyped BaseImage;
    ULONG TableRva, TableSize;
    ULONG Index;

    try {

        if (m_Image.Initialized) {

            //
            // Points to Data Directory Table.
            //

            TableRva = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            TableSize = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;

            if (TableRva && TableSize) {

                //
                // Category.Type
                //

                ImgResDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)m_Image.Image + TableRva);

                if (IsValidAddress((ULONG_PTR)ImgResDir) &&
                    IsValidAddress((ULONG_PTR)(ImgResDir + 1))) {

                    ImgResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ImgResDir + 1);

                    if (IsValidAddress((ULONG_PTR)ImgResDirEntry) &&
                        IsValidAddress((ULONG_PTR)(ImgResDirEntry + 1))) {

                        if (ImgResDir->NumberOfIdEntries > 26) {

                            ImgResDir->NumberOfIdEntries = 26;
                        }

                        for (Index = 0; Index < ImgResDir->NumberOfIdEntries; Index++) {

                            if (ImgResDirEntry[Index].Name == Type) {

                                break;
                            }
                        }

                        if ((Index != ImgResDir->NumberOfIdEntries) || ImgResDirEntry[Index].DataIsDirectory) {

                            //
                            // Sub-category.Name
                            //

                            ImgResDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)m_Image.Image + TableRva + ImgResDirEntry[Index].OffsetToDirectory);

                            if (IsValidAddress((ULONG_PTR)ImgResDir) &&
                                IsValidAddress((ULONG_PTR)(ImgResDir + 1))) {

                                ImgResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ImgResDir + 1);

                                if (IsValidAddress((ULONG_PTR)ImgResDirEntry) &&
                                    IsValidAddress((ULONG_PTR)(ImgResDirEntry + 1))) {

                                    if (ImgResDir->NumberOfIdEntries > 26) {

                                        ImgResDir->NumberOfIdEntries = 26;
                                    }

                                    for (Index = 0; Index < ImgResDir->NumberOfIdEntries; Index++) {

                                        if (ImgResDirEntry[Index].Name == Name) {

                                            break;
                                        }
                                    }

                                    if ((Index != ImgResDir->NumberOfIdEntries) || ImgResDirEntry[Index].DataIsDirectory) {

                                        //
                                        // Read first entry by default.
                                        //

                                        ImgResDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)m_Image.Image + TableRva + ImgResDirEntry[Index].OffsetToDirectory);

                                        if (IsValidAddress((ULONG_PTR)ImgResDir) &&
                                            IsValidAddress((ULONG_PTR)(ImgResDir + 1))) {

                                            ImgResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ImgResDir + 1);

                                            if (IsValidAddress((ULONG_PTR)ImgResDirEntry) &&
                                                IsValidAddress((ULONG_PTR)(ImgResDirEntry + 1))) {

                                                if (!ImgResDirEntry[0].DataIsDirectory) {

                                                    ImgResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((PUCHAR)m_Image.Image + TableRva + ImgResDirEntry[0].OffsetToDirectory);

                                                    if (IsValidAddress((ULONG_PTR)ImgResDataEntry) &&
                                                        IsValidAddress((ULONG_PTR)(ImgResDataEntry + 1))) {

                                                        RessourceData = malloc(ImgResDataEntry->Size);

                                                        if (RessourceData) {

                                                            if (IsValidAddress((ULONG_PTR)((PUCHAR)m_Image.Image + ImgResDataEntry->OffsetToData)) &&
                                                                IsValidAddress((ULONG_PTR)((PUCHAR)m_Image.Image + ImgResDataEntry->OffsetToData + ImgResDataEntry->Size))) {

                                                                memcpy_s(RessourceData, ImgResDataEntry->Size, (PUCHAR)m_Image.Image + ImgResDataEntry->OffsetToData, ImgResDataEntry->Size);
                                                            }
                                                            else {

                                                                free(RessourceData);

                                                                RessourceData = NULL;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    catch (...) {

    }

    return RessourceData;
}

BOOLEAN
MsPEImageFile::RtlGetPdbInfo(
    VOID
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
    PIMAGE_DEBUG_DIRECTORY DbgDir;
    PCV_INFO_PDB70 PdbInfo;
    ULONG_PTR ImageBase;
    ULONG TableRva, TableSize;

    try {

        if (m_Image.Initialized) {

            TableRva = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            TableSize = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

            if (TableRva && TableSize) {

                ImageBase = (ULONG_PTR)m_Image.Image;

                DbgDir = (PIMAGE_DEBUG_DIRECTORY)(ImageBase + TableRva);

                if (IsValidAddress((ULONG_PTR)DbgDir) &&
                    IsValidAddress((ULONG_PTR)(DbgDir + 1))) {

                    if (IsValidAddress(ImageBase + DbgDir->AddressOfRawData) &&
                        IsValidAddress(ImageBase + DbgDir->AddressOfRawData + DbgDir->SizeOfData)) {

                        PdbInfo = (PCV_INFO_PDB70)(ImageBase + DbgDir->AddressOfRawData);

                        if (PdbInfo->Signature == CV_SIGNATURE_RSDS) {

                            m_PdbInfo.Guid = PdbInfo->Guid;
                            m_PdbInfo.Age = PdbInfo->Age;

                            StringCchCopyA(m_PdbInfo.PdbName, _countof(m_PdbInfo.PdbName), PdbInfo->PdbFileName);

                            return TRUE;
                        }
                    }
                }
            }
        }
    }
    catch (...) {

    }

    return FALSE;
}

BOOLEAN
MsPEImageFile::RtlGetImports(
    vector<MsDllObject> &DllList
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
    PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor;
    WCHAR DllName[MAX_PATH];
    ULONG_PTR ImageBase;
    ULONG64 Address;
    ULONG ImportDescriptorIndex = 0;
    BOOL Is64BitTarget;
    BOOL Is32BitImage;

    ASSERTDBG(m_Image.Initialized);

    Is64BitTarget = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? TRUE : FALSE;
    Is32BitImage = m_Image.NtHeader32 ? TRUE : FALSE;

    if (m_Image.Initialized) {

        ImageBase = (ULONG_PTR)m_Image.Image;

        if (m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress && m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {

            ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ImageBase + m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

            if (IsValidAddress((ULONG_PTR)ImageImportDescriptor)) {

                try {

                    while(ImageImportDescriptor->OriginalFirstThunk ||
                          ImageImportDescriptor->TimeDateStamp ||
                          ImageImportDescriptor->ForwarderChain ||
                          ImageImportDescriptor->Name ||
                          ImageImportDescriptor->FirstThunk) {

                        IMPORT_DESCRIPTOR ImportDescriptor;
                        IMPORT_INFO ImportInfo = {0};
                        ULONG_PTR DllNameAddress;
                        ULONG64 DllImageBase = 0;
                        ULONG64 DllImageEnd = 0;

                        if (!IsValidAddress(ImageBase + ImageImportDescriptor->Name) ||
                            !IsValidAddress(ImageBase + ImageImportDescriptor->FirstThunk) ||
                            !IsValidAddress(ImageBase + ImageImportDescriptor->OriginalFirstThunk)) {

                            break;
                        }

                        DllNameAddress = ImageBase + ImageImportDescriptor->Name;

                        StringCchPrintfW(DllName, _countof(DllName), L"%S", (PSTR)DllNameAddress);

                        if (wcslen(DllName)) {

                            for (size_t i = 0; i < DllList.size(); i++) {

                                MsDllObject DllObject = DllList[i];

                                if (Is64BitTarget && Is32BitImage && !DllObject.mm_CcDllObject.IsWow64) {

                                    continue;
                                }

                                if (0 == _wcsicmp(DllName, DllObject.mm_CcDllObject.DllName)) {

                                    DllImageBase = DllObject.m_ImageBase;
                                    DllImageEnd = DllObject.m_ImageBase + DllObject.m_ImageSize;

                                    break;
                                }
                            }

                            StringCchCopy(ImportDescriptor.DllName, _countof(ImportDescriptor.DllName), (PSTR)DllNameAddress);
                        }
                        else {

                            StringCchPrintf(ImportDescriptor.DllName, _countof(ImportDescriptor.DllName), "%d", ImportDescriptorIndex);
                        }

                        if (ImageImportDescriptor->FirstThunk && ImageImportDescriptor->OriginalFirstThunk) {

                            ULONG_PTR ImportAddressTable = (ULONG_PTR)(ImageBase + ImageImportDescriptor->FirstThunk);
                            ULONG_PTR ImportNameTable = (ULONG_PTR)(ImageBase + ImageImportDescriptor->OriginalFirstThunk);

                            if (Is32BitImage) {

                                PULONG ImportAddressTable32 = (PULONG)ImportAddressTable;
                                PIMAGE_THUNK_DATA32 ImageThunkData32 = (PIMAGE_THUNK_DATA32)ImportNameTable;

                                while (*ImportAddressTable32) {

                                    Address = *ImportAddressTable32;

                                    if (!Is64BitTarget) {

                                        Address = DEBUG_EXTEND64(Address);
                                    }

                                    ImportInfo.AddressInfo.Address = Address;
                                    ImportInfo.AddressInfo.HookType = GetPointerHookType(Address);

                                    if (Address && DllImageBase && DllImageEnd) {

                                        ImportInfo.AddressInfo.IsTablePatched = (Address >= DllImageBase && Address < DllImageEnd) ? FALSE : TRUE;
                                    }

                                    if (g_Ext->m_Symbols->GetNameByOffset(Address, ImportInfo.Name, _countof(ImportInfo.Name), NULL, NULL) != S_OK) {

                                        if (ImageThunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {

                                            StringCchPrintf(ImportInfo.Name, _countof(ImportInfo.Name), "Ordinal %04X", (WORD)ImageThunkData32->u1.Ordinal);
                                        }
                                        else {

                                            PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)(ImageBase + ImageThunkData32->u1.AddressOfData);

                                            if (IsValidAddress((ULONG_PTR)ImageImportByName)) {

                                                StringCchCopy(ImportInfo.Name, _countof(ImportInfo.Name), ImageImportByName->Name);
                                            }
                                        }
                                    }

                                    if (ImportInfo.AddressInfo.IsTablePatched || ImportInfo.AddressInfo.HookType) {

                                        m_NumberOfHookedAPIs++;
                                    }

                                    ImportDescriptor.m_Imports.push_back(ImportInfo);

                                    m_NumberOfImportedFunctions++;

                                    ImportAddressTable32++;
                                    ImageThunkData32++;
                                }
                            }
                            else {

                                PULONG64 ImportAddressTable64 = (PULONG64)ImportAddressTable;
                                PIMAGE_THUNK_DATA64 ImageThunkData64 = (PIMAGE_THUNK_DATA64)ImportNameTable;

                                while (*ImportAddressTable64) {

                                    Address = *ImportAddressTable64;

                                    ImportInfo.AddressInfo.Address = Address;
                                    ImportInfo.AddressInfo.HookType = GetPointerHookType(Address);

                                    if (Address && DllImageBase && DllImageEnd) {

                                        ImportInfo.AddressInfo.IsTablePatched = (Address >= DllImageBase && Address < DllImageEnd) ? FALSE : TRUE;
                                    }

                                    if (g_Ext->m_Symbols->GetNameByOffset(Address, ImportInfo.Name, _countof(ImportInfo.Name), NULL, NULL) != S_OK) {

                                        if (ImageThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {

                                            StringCchPrintf(ImportInfo.Name, _countof(ImportInfo.Name), "Ordinal %04X", (WORD)ImageThunkData64->u1.Ordinal);
                                        }
                                        else {

                                            PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)(ImageBase + ImageThunkData64->u1.AddressOfData);

                                            if (IsValidAddress((ULONG_PTR)ImageImportByName)) {

                                                StringCchCopy(ImportInfo.Name, _countof(ImportInfo.Name), ImageImportByName->Name);
                                            }
                                        }
                                    }

                                    if (ImportInfo.AddressInfo.IsTablePatched || ImportInfo.AddressInfo.HookType) {

                                        m_NumberOfHookedAPIs++;
                                    }

                                    ImportDescriptor.m_Imports.push_back(ImportInfo);

                                    m_NumberOfImportedFunctions++;

                                    ImportAddressTable64++;
                                    ImageThunkData64++;
                                }
                            }
                        }

                        m_ImportDescriptors.push_back(ImportDescriptor);

                        ImageImportDescriptor++;
                        ImportDescriptorIndex++;
                    }

                    return TRUE;
                }
                catch (...) {

                }
            }
        }
    }

    return FALSE;
}

BOOLEAN
MsPEImageFile::RtlGetExports(
    VOID
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
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    ULONG_PTR ImageBase;
    PULONG AddressOfNames;
    PULONG AddressOfFunctions;
    PUSHORT AddressOfNameOrdinals;
    ULONG TableRva, TableSize;
    ULONG NumberOfHookedAPIs = 0;
    ULONG i;

    try {

        if (m_Image.Initialized) {

            TableRva = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            TableSize = m_Image.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            if (TableRva && TableSize) {

                ImageBase = (ULONG_PTR)m_Image.Image;

                if (IsValidAddress(ImageBase + TableRva) &&
                    IsValidAddress(ImageBase + TableRva + TableSize)) {

                    ExportDir = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + TableRva);

                    if ((ExportDir->AddressOfNames >= TableRva && ExportDir->AddressOfNames < (TableRva + TableSize)) &&
                        (ExportDir->AddressOfNameOrdinals >= TableRva && ExportDir->AddressOfNameOrdinals < (TableRva + TableSize)) &&
                        (ExportDir->AddressOfFunctions >= TableRva && ExportDir->AddressOfFunctions < (TableRva + TableSize))) {

                        AddressOfNames = (PULONG)(ImageBase + ExportDir->AddressOfNames);
                        AddressOfFunctions = (PULONG)(ImageBase + ExportDir->AddressOfFunctions);
                        AddressOfNameOrdinals = (PUSHORT)(ImageBase + ExportDir->AddressOfNameOrdinals);

#if VERBOSE_MODE
                        g_Ext->Dml("(%s) ExportDir->NumberOfName: %d, ExportDir->NumberOfFunctions: %d\n",
                                   m_PdbInfo.PdbName,
                                   ExportDir->NumberOfNames,
                                   ExportDir->NumberOfFunctions);
#endif

                        if (IsValidAddress((ULONG_PTR)AddressOfNames) &&
                            IsValidAddress((ULONG_PTR)AddressOfNames + ExportDir->NumberOfNames * sizeof(DWORD)) &&
                            IsValidAddress((ULONG_PTR)AddressOfFunctions) &&
                            IsValidAddress((ULONG_PTR)AddressOfFunctions + ExportDir->NumberOfFunctions * sizeof(DWORD)) &&
                            IsValidAddress((ULONG_PTR)AddressOfNameOrdinals) &&
                            IsValidAddress((ULONG_PTR)AddressOfNameOrdinals + ExportDir->NumberOfNames * sizeof(DWORD))) {

                            m_NumberOfExportedFunctions = ExportDir->NumberOfNames;

                            for (i = 0; i < ExportDir->NumberOfNames; i++) {

                                if (AddressOfNameOrdinals[i] >= ExportDir->NumberOfNames) {

                                    continue;
                                }

                                if (IsValidAddress((ULONG_PTR)(AddressOfFunctions + AddressOfNameOrdinals[i])) &&
                                    IsValidAddress((ULONG_PTR)(AddressOfFunctions + AddressOfNameOrdinals[i] + sizeof(ULONG)))) {

                                    EXPORT_INFO ExportInfo = {0};

                                    ExportInfo.Index = i;
                                    ExportInfo.Ordinal = AddressOfNameOrdinals[i];

                                    GetAddressInfo(m_ImageBase + AddressOfFunctions[AddressOfNameOrdinals[i]], &ExportInfo.AddressInfo);

                                    if (ExportInfo.AddressInfo.IsTablePatched || ExportInfo.AddressInfo.HookType) {

                                        NumberOfHookedAPIs++;
                                    }

                                    if (IsValidAddress(ImageBase + AddressOfNames[i])) {

                                        try {

                                            StringCchCopyA(ExportInfo.Name, _countof(ExportInfo.Name), (PCSTR)(ImageBase + AddressOfNames[i]));
                                        }
                                        catch (...) {

                                        }
                                    }

                                    m_Exports.push_back(ExportInfo);
                                }
                            }

                            m_NumberOfHookedAPIs = NumberOfHookedAPIs;

                            return TRUE;
                        }
                    }
                }
            }
        }
    }
    catch (...) {

    }

    return FALSE;
}

BOOLEAN
MsPEImageFile::RtlGetFileVersion(
    VOID
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
    PVOID Description;
    PLANGANDCODEPAGE Translation;
    WCHAR MagicLine[MAX_PATH];
    UINT TranslateSize;
    UINT DescriptionSize;
    BOOL Result = TRUE;

    try {

        RessourceData = RtlGetRessourceData(VS_VERSION_INFO, (ULONG)((ULONG_PTR)RT_VERSION));

        if (RessourceData == NULL) goto CleanUp;

        //
        // Read the list of languages and code pages.
        //

        Result = VerQueryValueW(RessourceData,
                                L"\\VarFileInfo\\Translation",
                                (LPVOID*)&Translation,
                                &TranslateSize);

        if (!Result || Translation == NULL) goto CleanUp;

        //
        // Product Version
        //

        swprintf_s(MagicLine,
                   _countof(MagicLine),
                   L"\\StringFileInfo\\%04x%04x\\ProductVersion",
                   Translation->wLanguage,
                   Translation->wCodePage);

        VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);

        if (DescriptionSize) {

            swprintf_s(m_FileVersion.ProductVersion, _countof(m_FileVersion.ProductVersion), L"%s", (PWSTR)Description);
        }

        //
        // File Version
        //

        swprintf_s(MagicLine,
                   _countof(MagicLine),
                   L"\\StringFileInfo\\%04x%04x\\FileVersion",
                   Translation->wLanguage,
                   Translation->wCodePage);

        VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);

        if (DescriptionSize) {

            swprintf_s(m_FileVersion.FileVersion, _countof(m_FileVersion.FileVersion), L"%s", (PWSTR)Description);
        }

        //
        // Company Name
        //

        swprintf_s(MagicLine,
                   _countof(MagicLine),
                   L"\\StringFileInfo\\%04x%04x\\CompanyName",
                   Translation->wLanguage,
                   Translation->wCodePage);

        VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);

        if (DescriptionSize) {

            swprintf_s(m_FileVersion.CompanyName, _countof(m_FileVersion.CompanyName), L"%s", (PWSTR)Description);
        }

        //
        // File Description
        //

        swprintf_s(MagicLine,
                   _countof(MagicLine),
                   L"\\StringFileInfo\\%04x%04x\\FileDescription",
                   Translation->wLanguage,
                   Translation->wCodePage);

        VerQueryValueW(RessourceData, MagicLine, &Description, &DescriptionSize);

        if (DescriptionSize) {

            swprintf_s(m_FileVersion.FileDescription, _countof(m_FileVersion.FileDescription), L"%s", (PWSTR)Description);
        }

    #if VERBOSE_MODE
        // g_Ext->Dml("FileDesc: %S\n", ProcessObject.m_CcProcessObject.FileDescription);
    #endif

        Result = TRUE;
    }
    catch (...) {

    }

CleanUp:

    if (RessourceData) free(RessourceData);

    return (BOOLEAN)Result;
}

BOOLEAN
MsPEImageFile::RtlGetSections(
    VOID
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
    ULONG_PTR ImageBase;
    ULONG_PTR Address;
    ULONG Index;

    for (Index = 0; Index < m_Image.NumberOfSections; Index++) {

        CACHED_SECTION_INFO SectionInfo = {0};
        MD5_CONTEXT Md5Context = {0};

        try {

            memcpy_s(SectionInfo.Name, sizeof(SectionInfo.Name), m_Image.Sections[Index].Name, sizeof(m_Image.Sections[Index].Name));

            SectionInfo.VaBase = m_Image.Sections[Index].VirtualAddress;
            SectionInfo.VaSize = m_Image.Sections[Index].Misc.VirtualSize;
            SectionInfo.RawSize = m_Image.Sections[Index].SizeOfRawData;
            SectionInfo.Characteristics = m_Image.Sections[Index].Characteristics;

            if (m_Image.Sections[Index].Characteristics & IMAGE_SCN_MEM_EXECUTE) {

                SectionInfo.IsExecutable = TRUE;
            }

            if (g_Verbose) g_Ext->Dml("[%d][%s] Base = 0x%I64X Size = 0x%x RawSize = 0x%x\n", Index, SectionInfo.Name, SectionInfo.VaBase, SectionInfo.VaSize, SectionInfo.RawSize);

            ImageBase = (ULONG_PTR)m_Image.Image;

            Address = ImageBase + SectionInfo.VaBase;

            if (Address >= ImageBase && Address < (ImageBase + m_ImageSize)) {

                Address = ImageBase + SectionInfo.VaBase + SectionInfo.VaSize;

                if (Address >= ImageBase && Address < (ImageBase + m_ImageSize)) {

                    MD5Init(&Md5Context);
                    MD5Update(&Md5Context, (PUCHAR)(ImageBase + SectionInfo.VaBase), SectionInfo.VaSize);
                    MD5Final(&Md5Context);

                    memcpy_s(SectionInfo.VaMd5Hash, sizeof(SectionInfo.VaMd5Hash), Md5Context.Digest, sizeof(Md5Context.Digest));

#if VERBOSE_MODE
                    g_Ext->Dml("Md5: ");
                    for (UINT i = 0; i < 16; i++) g_Ext->Dml("%02x", Md5Context.Digest[i]);
                    g_Ext->Dml("\n");
#endif
                }

                Address = ImageBase + SectionInfo.VaBase + SectionInfo.RawSize;

                if (Address >= ImageBase && Address < (ImageBase + m_ImageSize)) {

                    MD5Init(&Md5Context);
                    MD5Update(&Md5Context, (PUCHAR)(ImageBase + SectionInfo.VaBase), SectionInfo.RawSize);
                    MD5Final(&Md5Context);

                    memcpy_s(SectionInfo.RawMd5Hash, sizeof(SectionInfo.RawMd5Hash), Md5Context.Digest, sizeof(Md5Context.Digest));

#if VERBOSE_MODE
                    g_Ext->Dml("Md5: ");
                    for (UINT i = 0; i < 16; i++) g_Ext->Dml("%02x", Md5Context.Digest[i]);
                    g_Ext->Dml("\n");
#endif
                }
            }

            // VirusTotal::GetReport(Md5Context.Digest);

            m_CcSections.push_back(SectionInfo);
        }
        catch (...) {

        }
    }

    return TRUE;
}

BOOLEAN
MsPEImageFile::InitImage(
    VOID
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
    ExtRemoteTyped BaseImage;
    BOOLEAN Result = FALSE;
    HRESULT Status;

    try {

        if (m_Image.Initialized)
        {
            // g_Ext->Dml("b_Initialized already set to TRUE\n");
            Result = TRUE;
            goto CleanUp;
        }

        BaseImage = ExtRemoteTyped("(nt!_IMAGE_DOS_HEADER *)@$extin", BaseImageAddress);

        if (BaseImage.Field("e_magic").GetUshort() != IMAGE_DOS_SIGNATURE) {

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

            NtHeader32 = (PIMAGE_NT_HEADERS32)((PUCHAR)Header + BaseImage.Field("e_lfanew").GetUlong());

            if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                m_ImageSize = NtHeader32->OptionalHeader.SizeOfImage;
            }
            else if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader32;
                NtHeader32 = NULL;
                m_ImageSize = NtHeader64->OptionalHeader.SizeOfImage;
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

        Status = ExtRemoteTypedEx::ReadImageMemory(BaseImageAddress, Image, (ULONG)m_ImageSize, &BytesRead);

        if (Status == E_ACCESSDENIED) {

            m_IsPagedOut = TRUE;
        }
        else if (Status != S_OK)
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

	    m_IsSigned = ((PIMAGE_DATA_DIRECTORY)m_Image.DataDirectory)[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress ? TRUE : FALSE;

#if VERBOSE_MODE
    g_Ext->Dml("m_Image = %p\n"
        "m_NtHeader32 = %p\n"
        "m_DataDirectory = %p\n"
        "m_Sections = %p\n", m_Image.Image, m_Image.NtHeader32, m_Image.DataDirectory, m_Image.Sections);

    g_Ext->Dml("m_NumberOfSections = %x\n", m_Image.NumberOfSections);
#endif

        Result = TRUE;
    }
    catch (...) {

    }

CleanUp:
    if (Header) free(Header);

    m_Image.Initialized = Result;

    return Result;
}

BOOLEAN
MsPEImageFile::GetInfoFull(
    VOID
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
