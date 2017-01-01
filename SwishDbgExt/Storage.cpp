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

    - Storage.cpp

    - Store Manager (Sm*) is pretty new under Windows 7/Windows 2008 R2 kernel, this is a new management system to deal with both virtual
    and physical stores. ReadyBoost (cache/files/logs, …) is one exemple. Even through ReadyBoost had been firstly introduced into Windows
    Vista and Windows 2008 (Refer to Mark Russinovich writeup about Windows Vista Kernel for more information about ReadyBoost), Microsoft
    kernel developpers implemented ReadyBoost feature inside the Store Manager to make it more efficient.
    http://www.msuiche.net/2009/12/06/sminfo-inside-store-manager-of-windows-7-and-windows-2008-r2-with-windd/

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

//
// Store Manager (sminfo, ReadyBoost, etc..)
// MountMgr
//

#include "stdafx.h"
#include "SwishDbgExt.h"

StoreManager::StoreManager(
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    None.

--*/
{
    m_SmLogCtxOffset = GetFieldOffset("nt!_SM_GLOBALS", "StoreMgr.Log");
    m_SmcCacheMgrOffset = GetFieldOffset("nt!_SM_GLOBALS", "CacheMgr");

    if (!m_SmLogCtxOffset || !m_SmcCacheMgrOffset)
    {
        g_Ext->Dml("Error: Can't retrieve Store and Cache offsets.\n");
    }

    m_SmGlobalsAddress = 0;

    if (g_Ext->m_Control->IsPointer64Bit() == S_OK)
    {
        m_SmpLogBufferSize = sizeof(SMP_LOG_BUFFER64);
        m_SmLogEntrySize = sizeof(SM_LOG_ENTRY64);
    }
    else
    {
        m_SmpLogBufferSize = sizeof(SMP_LOG_BUFFER32);
        m_SmLogEntrySize = sizeof(SM_LOG_ENTRY32);
    }

    g_Ext->m_Symbols->GetOffsetByName("nt!SmGlobals", &m_SmGlobalsAddress);
}

LPSTR LogEntryType[] = { "Add",
                        "Remove",
                        "Full",
                        "Update" };

BOOLEAN
StoreManager::GetSmLogEntries(
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
//    SMP_LOG_BUFFER32 Log32;
    SMP_LOG_BUFFER64 Log64;
    ULONG64 SmLogBuffer = ExtRemoteTypedEx::GetPointer(m_SmGlobalsAddress + m_SmLogCtxOffset);
    ULONG64 SmLogBufferNext;
    ULONG BytesRead;

    PSM_LOG_ENTRY32 pLogEntry32 = NULL, le32 = NULL;
    PSM_LOG_ENTRY64 pLogEntry64 = NULL, le64 = NULL;

    SM_LOG_ENTRY64 LogEntry;

    BOOLEAN Is64Bit = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? TRUE : FALSE;

    BOOLEAN Result = FALSE;

    if (!SmLogBuffer)
    {
        goto CleanUp;
    }

    g_Ext->Dml("<col fg=\"changed\">"
               "  ID # Action    EPROCESS             Application Name  Page Count  Priority  Virtual Address Range"
               "</col>\n"
               "   ---- ------   ------------------   ----------------  ----------  --------  -------------------------------------\n");

    while (SmLogBuffer)
    {
        ULONG EntryCount, EntryMax;

        // g_Ext->Dml("SmLogBuffer = 0x%I64X m_SmpLogBufferSize = 0x%x\n", SmLogBuffer, m_SmpLogBufferSize);

        if (ExtRemoteTypedEx::ReadVirtual(SmLogBuffer, &Log64, m_SmpLogBufferSize, &BytesRead) != S_OK)
        {
            g_Ext->Err("Error1: Failed to read log.\n");
            goto CleanUp;
        }

        if (Is64Bit)
        {
            EntryCount = Log64.EntryCount;
            EntryMax = Log64.EntryMax;
            SmLogBufferNext = Log64.Link;
        }
        else
        {
            EntryCount = ((PSMP_LOG_BUFFER32)&Log64)->EntryCount;
            SmLogBufferNext = ((PSMP_LOG_BUFFER32)&Log64)->Link;
        }

        if (EntryCount == 0)
        {
            // g_Ext->DmlWarn("Store Manager logs are empty.\n");
            goto CleanUp;
        }

        // g_Ext->Dml("SmLogBuffer = %I64X, EntryCount = %d, EntryMax = %d\n", EntryCount, EntryMax);

        pLogEntry64 = (PSM_LOG_ENTRY64)malloc(EntryCount * m_SmLogEntrySize);
        if (pLogEntry64 == NULL) goto CleanUp;

        if (!Is64Bit)
        {
            pLogEntry32 = (PSM_LOG_ENTRY32)pLogEntry64;
            pLogEntry64 = NULL;
        }

        if (ExtRemoteTypedEx::ReadVirtual(SmLogBuffer + m_SmpLogBufferSize,
                                          (pLogEntry64) ? (PVOID)pLogEntry64 : (PVOID)pLogEntry32,
                                          EntryCount * m_SmLogEntrySize,
                                          &BytesRead) != S_OK)
        {
            g_Ext->Err("Error2: Failed to read log. (p = %I64X, 0x%x)\n",
                        SmLogBuffer + m_SmpLogBufferSize,
                        EntryCount * m_SmLogEntrySize);
            goto CleanUp;
        }

        for (ULONG Index = 0; Index < EntryCount; Index += 1)
        {
            if (pLogEntry64) le64 = &pLogEntry64[Index];
            else le32 = &pLogEntry32[Index];

            RtlZeroMemory(&LogEntry, sizeof(LogEntry));

            if (le32)
            {
                LogEntry.PageCount = le32->PageCount;
                LogEntry.AllFlags = le32->AllFlags;
                LogEntry.KeyDescriptor.ProcessKey = le32->KeyDescriptor.ProcessKey;
                LogEntry.KeyDescriptor.VirtualAddress = le32->KeyDescriptor.VirtualAddress;
            }
            else
            {
                LogEntry = *le64;
            }

            if ((LogEntry.KeyDescriptor.Flags.PageType == SmPageTypeProcess) &&
                IsValid(LogEntry.KeyDescriptor.ProcessKey))
            {
                CHAR ImageName[17] = { 0 };

                ExtRemoteTyped OwningProcess("(nt!_EPROCESS *)@$extin", LogEntry.KeyDescriptor.ProcessKey);

                OwningProcess.Field("ImageFileName").GetString((LPSTR)ImageName, sizeof(ImageName));

                g_Ext->Dml("   %4d %-8s <link cmd=\"!dml_proc 0x%I64X\">0x%016I64X</link>   <col fg=\"emphfg\">%-16s</col>  %10d  P%-8d 0x%016I64X-0x%016I64X\n",
                    Index,
                    LogEntryType[LogEntry.Flags.Type],
                    LogEntry.KeyDescriptor.ProcessKey,
                    LogEntry.KeyDescriptor.ProcessKey,
                    ImageName,
                    LogEntry.PageCount,
                    LogEntry.Flags.Priority,
                    LogEntry.KeyDescriptor.VirtualAddress * PAGE_SIZE,
                    (LogEntry.KeyDescriptor.VirtualAddress + LogEntry.PageCount) * PAGE_SIZE);

            }

            SmLogEntries.push_back(LogEntry);

            SmLogBuffer = SmLogBufferNext;
        }

        // SmLogBuffer initialized above.
    }

    Result = TRUE;

CleanUp:
    if (Result == FALSE)
    {
        g_Ext->Warn("-> Storage manager logs are empty!\n");
    }

    if (pLogEntry64) free(pLogEntry64);
    if (pLogEntry32) free(pLogEntry32);

    return Result;
}

BOOL
StoreManager::SmiDisplayCacheInformation(
    _In_ ULONG64 CacheManager,
    _In_ ULONG CacheIndex
)
/*++

Routine Description:

    Description.

Arguments:

    CacheManager -
    CacheIndex - 

Return Value:

    BOOLEAN.

--*/
{
    WCHAR UniqueId[256 + 1] = { 0 };

    ExtRemoteUnTyped CacheRef(CacheManager, "nt!_SMC_CACHE_REF");
    ULONG64 CachePtr = CacheRef.ArrayElement(CacheIndex).Field("Cache").GetPtr();
    if (CachePtr == 0) return FALSE;

    if (!IsValid(CachePtr)) return FALSE;

    ExtRemoteUnTyped CacheEntry(CachePtr, "nt!_SMC_CACHE");

    g_Ext->Dml("<col fg=\"changed\">Cache @ 0x%I64X</col>\n", CachePtr);

    ULONG64 CacheFileSize = CacheEntry.Field("CacheParams.CacheFileSize").GetUlong64();
    ULONG64 FileHandle = CacheEntry.Field("FileInfo.FileHandle").GetPtr();
    ULONG64 FileObject = CacheEntry.Field("FileInfo.FileObject").GetPtr();

    g_Ext->Dml("    CacheIndex: %d# Store Manager cache file size = %I64d bytes (%d Mb) (%d Gb)\n",
        CacheIndex,
        CacheFileSize,
        CacheFileSize / (1024 * 1024),
        CacheFileSize / (1024 * 1024 * 1024));
    g_Ext->Dml("    Handle: <link cmd=\"!handle 0x%I64X\">0x%I64X</link>\n"
               "    FileObject: <link cmd=\"!fileobj 0x%I64X\">0x%I64X</link> (<link cmd=\"dt nt!_FILE_OBJECT 0x%I64X -b\">more</link>)\n",
               FileHandle, FileHandle,
               FileObject, FileObject, FileObject);
    g_Ext->Dml("    ID: %ws\n\n", CacheEntry.Field("UniqueId").GetString(UniqueId, _countof(UniqueId)));

    return TRUE;
}

VOID
StoreManager::SmiEnumCaches(
    ULONG CacheIndex
)
/*++

Routine Description:

    Description.

Arguments:

    CacheIndex - 

Return Value:

    None.

--*/
{
    ULONG Index;

    if (CacheIndex == (ULONG)-1)
    {
        for (Index = 0; Index < SM_STORES_MAX; Index += 1)
        {
            SmiDisplayCacheInformation(m_SmGlobalsAddress + m_SmcCacheMgrOffset, Index);
        }
    }
    else
    {
        if (SmiDisplayCacheInformation(m_SmGlobalsAddress + m_SmcCacheMgrOffset, CacheIndex) == FALSE)
        {
            g_Ext->Warn("-> No Store Manager associated to this ID.\n");
        }
    }
}
