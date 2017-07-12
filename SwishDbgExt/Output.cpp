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

    - Output.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx
    - TODO: set symbols noisy

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"

VOID
OutThread(
    _In_ PTHREAD_OBJECT Thread
)
/*++

Routine Description:

    Description.

Arguments:

    Thread - 

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(Thread);
}

VOID
OutHandles(
    _In_ PHANDLE_OBJECT Handle
)
/*++

Routine Description:

    Description.

Arguments:

    Handle - 

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(Handle);
}

LPSTR IrpMajor[] = {
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
    NULL };

VOID
OutDriver(
    _In_ MsDriverObject *Driver,
    _In_ ULONG ExpandFlag
)
/*++

Routine Description:

    Description.

Arguments:

    Driver - 
    ExpandFlag -

Return Value:

    ULONG64.

--*/
{
    MsDriverObject::PFAST_IO_DISPATCH FastIo = NULL;
    UCHAR Name[512] = { 0 };

    g_Ext->Dml("    | <col fg=\"emphfg\">%-32S</col> | <link cmd=\"!ms_drivers /object 0x%016I64X\">0x%016I64x</link> | 0x%08X | %S\n",
        Driver->mm_DriverInfo.DriverName, Driver->m_ObjectPtr,
        Driver->m_ImageBase, Driver->m_ImageSize,
        Driver->mm_DriverInfo.FullDllName);

    if (!ExpandFlag) return;

    for (UINT i = 0; IrpMajor[i]; i += 1)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   IrpMajor[i], Driver->mm_DriverInfo.MajorFunction[i].Address,
                   GetPointerHookType(Driver->mm_DriverInfo.MajorFunction[i].Address) ? "Hooked" : "",
                   GetNameByOffset(Driver->mm_DriverInfo.MajorFunction[i].Address, (LPSTR)Name, _countof(Name)));
    }

    FastIo = &Driver->mm_DriverInfo.FastIoDispatch;

    if (FastIo->FastIoCheckIfPossible.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoCheckIfPossible",
                   FastIo->FastIoCheckIfPossible.Address,
                   GetPointerHookType(FastIo->FastIoCheckIfPossible.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoCheckIfPossible.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoRead.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoRead",
                   FastIo->FastIoRead.Address,
                   GetPointerHookType(FastIo->FastIoRead.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoRead.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoWrite.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoWrite",
                   FastIo->FastIoWrite.Address,
                   GetPointerHookType(FastIo->FastIoWrite.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoWrite.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryBasicInfo.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoQueryBasicInfo",
                   FastIo->FastIoQueryBasicInfo.Address,
                   GetPointerHookType(FastIo->FastIoQueryBasicInfo.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoQueryBasicInfo.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryStandardInfo.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoQueryStandardInfo",
                   FastIo->FastIoQueryStandardInfo.Address,
                   GetPointerHookType(FastIo->FastIoQueryStandardInfo.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoQueryStandardInfo.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoLock.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoLock",
                   FastIo->FastIoLock.Address,
                   GetPointerHookType(FastIo->FastIoLock.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoLock.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoUnlockSingle.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoUnlockSingle",
                   FastIo->FastIoUnlockSingle.Address,
                   GetPointerHookType(FastIo->FastIoUnlockSingle.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoUnlockSingle.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoUnlockAll.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoUnlockAll",
                   FastIo->FastIoUnlockAll.Address,
                   GetPointerHookType(FastIo->FastIoUnlockAll.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoUnlockAll.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoUnlockAllByKey.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoUnlockAllByKey",
                   FastIo->FastIoUnlockAllByKey.Address,
                   GetPointerHookType(FastIo->FastIoUnlockAllByKey.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoUnlockAllByKey.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoDeviceControl.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoDeviceControl",
                   FastIo->FastIoDeviceControl.Address,
                   GetPointerHookType(FastIo->FastIoDeviceControl.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoDeviceControl.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireFileForNtCreateSection.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "AcquireFileForNtCreateSection",
                   FastIo->AcquireFileForNtCreateSection.Address,
                   GetPointerHookType(FastIo->AcquireFileForNtCreateSection.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->AcquireFileForNtCreateSection.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireFileForNtCreateSection.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "AcquireFileForNtCreateSection",
                   FastIo->AcquireFileForNtCreateSection.Address,
                   GetPointerHookType(FastIo->AcquireFileForNtCreateSection.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->AcquireFileForNtCreateSection.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->ReleaseFileForNtCreateSection.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "ReleaseFileForNtCreateSection",
                   FastIo->ReleaseFileForNtCreateSection.Address,
                   GetPointerHookType(FastIo->ReleaseFileForNtCreateSection.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->ReleaseFileForNtCreateSection.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoDetachDevice.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoDetachDevice",
                   FastIo->FastIoDetachDevice.Address,
                   GetPointerHookType(FastIo->FastIoDetachDevice.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoDetachDevice.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryNetworkOpenInfo.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoQueryNetworkOpenInfo",
                   FastIo->FastIoQueryNetworkOpenInfo.Address,
                   GetPointerHookType(FastIo->FastIoQueryNetworkOpenInfo.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoQueryNetworkOpenInfo.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireForModWrite.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "AcquireForModWrite",
                   FastIo->AcquireForModWrite.Address,
                   GetPointerHookType(FastIo->AcquireForModWrite.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->AcquireForModWrite.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlRead.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "MdlRead",
                   FastIo->MdlRead.Address,
                   GetPointerHookType(FastIo->MdlRead.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->MdlRead.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlReadComplete.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "MdlReadComplete",
                   FastIo->MdlReadComplete.Address,
                   GetPointerHookType(FastIo->MdlReadComplete.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->MdlReadComplete.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->PrepareMdlWrite.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "PrepareMdlWrite",
                   FastIo->PrepareMdlWrite.Address,
                   GetPointerHookType(FastIo->PrepareMdlWrite.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->PrepareMdlWrite.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlWriteComplete.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "MdlWriteComplete",
                   FastIo->MdlWriteComplete.Address,
                   GetPointerHookType(FastIo->MdlWriteComplete.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->MdlWriteComplete.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoReadCompressed.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoReadCompressed",
                   FastIo->FastIoReadCompressed.Address,
                   GetPointerHookType(FastIo->FastIoReadCompressed.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoReadCompressed.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoWriteCompressed.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoWriteCompressed",
                   FastIo->FastIoWriteCompressed.Address,
                   GetPointerHookType(FastIo->FastIoWriteCompressed.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoWriteCompressed.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlReadCompleteCompressed.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "MdlReadCompleteCompressed",
                   FastIo->MdlReadCompleteCompressed.Address,
                   GetPointerHookType(FastIo->MdlReadCompleteCompressed.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->MdlReadCompleteCompressed.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlWriteCompleteCompressed.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "MdlWriteCompleteCompressed",
                   FastIo->MdlWriteCompleteCompressed.Address,
                   GetPointerHookType(FastIo->MdlWriteCompleteCompressed.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->MdlWriteCompleteCompressed.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryOpen.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "FastIoQueryOpen",
                   FastIo->FastIoQueryOpen.Address,
                   GetPointerHookType(FastIo->FastIoQueryOpen.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->FastIoQueryOpen.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->ReleaseForModWrite.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "ReleaseForModWrite",
                   FastIo->ReleaseForModWrite.Address,
                   GetPointerHookType(FastIo->ReleaseForModWrite.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->ReleaseForModWrite.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireForCcFlush.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "AcquireForCcFlush",
                   FastIo->AcquireForCcFlush.Address,
                   GetPointerHookType(FastIo->AcquireForCcFlush.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->AcquireForCcFlush.Address, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->ReleaseForCcFlush.Address)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
                   "ReleaseForCcFlush",
                   FastIo->ReleaseForCcFlush.Address,
                   GetPointerHookType(FastIo->ReleaseForCcFlush.Address) ? "Hooked" : "",
                   GetNameByOffset(FastIo->ReleaseForCcFlush.Address, (LPSTR)Name, _countof(Name)));
    }
}

LPSTR
GetLastWriteTime(
    PFILETIME ftWrite,
    LPSTR Buffer, 
    ULONG dwSize
)
{
    
    SYSTEMTIME stUTC, stLocal;

    if (Buffer && dwSize) {
        RtlZeroMemory(Buffer, dwSize);

        // Convert the last-write time to local time.
        FileTimeToSystemTime(ftWrite, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

        // Build a string showing the date and time.
        sprintf_s(Buffer, dwSize,
            "%02d/%02d/%d  %02d:%02d UTC",
            stLocal.wMonth, stLocal.wDay, stLocal.wYear,
            stLocal.wHour, stLocal.wMinute);
    }
    return Buffer;
}