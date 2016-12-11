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
            IrpMajor[i], Driver->mm_DriverInfo.MajorFunction[i],
            IsPointerHooked(Driver->mm_DriverInfo.MajorFunction[i]) ? "Hooked" : "",
            GetNameByOffset(Driver->mm_DriverInfo.MajorFunction[i], (LPSTR)Name, _countof(Name)));
    }

    FastIo = &Driver->mm_DriverInfo.FastIoDispatch;

    if (FastIo->FastIoCheckIfPossible)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoCheckIfPossible",
            FastIo->FastIoCheckIfPossible,
            IsPointerHooked(FastIo->FastIoCheckIfPossible) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoCheckIfPossible, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoRead)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoRead",
            FastIo->FastIoRead,
            IsPointerHooked(FastIo->FastIoRead) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoRead, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoWrite)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoWrite",
            FastIo->FastIoWrite,
            IsPointerHooked(FastIo->FastIoWrite) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoWrite, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryBasicInfo)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoQueryBasicInfo",
            FastIo->FastIoQueryBasicInfo,
            IsPointerHooked(FastIo->FastIoQueryBasicInfo) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoQueryBasicInfo, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryStandardInfo)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoQueryStandardInfo",
            FastIo->FastIoQueryStandardInfo,
            IsPointerHooked(FastIo->FastIoQueryStandardInfo) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoQueryStandardInfo, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoLock)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoLock",
            FastIo->FastIoLock,
            IsPointerHooked(FastIo->FastIoLock) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoLock, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoUnlockSingle)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoUnlockSingle",
            FastIo->FastIoUnlockSingle,
            IsPointerHooked(FastIo->FastIoUnlockSingle) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoUnlockSingle, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoUnlockAll)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoUnlockAll",
            FastIo->FastIoUnlockAll,
            IsPointerHooked(FastIo->FastIoUnlockAll) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoUnlockAll, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoUnlockAllByKey)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoUnlockAllByKey",
            FastIo->FastIoUnlockAllByKey,
            IsPointerHooked(FastIo->FastIoUnlockAllByKey) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoUnlockAllByKey, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoDeviceControl)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoDeviceControl",
            FastIo->FastIoDeviceControl,
            IsPointerHooked(FastIo->FastIoDeviceControl) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoDeviceControl, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireFileForNtCreateSection)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "AcquireFileForNtCreateSection",
            FastIo->AcquireFileForNtCreateSection,
            IsPointerHooked(FastIo->AcquireFileForNtCreateSection) ? "Hooked" : "",
            GetNameByOffset(FastIo->AcquireFileForNtCreateSection, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireFileForNtCreateSection)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "AcquireFileForNtCreateSection",
            FastIo->AcquireFileForNtCreateSection,
            IsPointerHooked(FastIo->AcquireFileForNtCreateSection) ? "Hooked" : "",
            GetNameByOffset(FastIo->AcquireFileForNtCreateSection, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->ReleaseFileForNtCreateSection)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "ReleaseFileForNtCreateSection",
            FastIo->ReleaseFileForNtCreateSection,
            IsPointerHooked(FastIo->ReleaseFileForNtCreateSection) ? "Hooked" : "",
            GetNameByOffset(FastIo->ReleaseFileForNtCreateSection, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoDetachDevice)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoDetachDevice",
            FastIo->FastIoDetachDevice,
            IsPointerHooked(FastIo->FastIoDetachDevice) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoDetachDevice, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryNetworkOpenInfo)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoQueryNetworkOpenInfo",
            FastIo->FastIoQueryNetworkOpenInfo,
            IsPointerHooked(FastIo->FastIoQueryNetworkOpenInfo) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoQueryNetworkOpenInfo, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireForModWrite)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "AcquireForModWrite",
            FastIo->AcquireForModWrite,
            IsPointerHooked(FastIo->AcquireForModWrite) ? "Hooked" : "",
            GetNameByOffset(FastIo->AcquireForModWrite, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlRead)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "MdlRead",
            FastIo->MdlRead,
            IsPointerHooked(FastIo->MdlRead) ? "Hooked" : "",
            GetNameByOffset(FastIo->MdlRead, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlReadComplete)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "MdlReadComplete",
            FastIo->MdlReadComplete,
            IsPointerHooked(FastIo->MdlReadComplete) ? "Hooked" : "",
            GetNameByOffset(FastIo->MdlReadComplete, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->PrepareMdlWrite)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "PrepareMdlWrite",
            FastIo->PrepareMdlWrite,
            IsPointerHooked(FastIo->PrepareMdlWrite) ? "Hooked" : "",
            GetNameByOffset(FastIo->PrepareMdlWrite, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlWriteComplete)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "MdlWriteComplete",
            FastIo->MdlWriteComplete,
            IsPointerHooked(FastIo->MdlWriteComplete) ? "Hooked" : "",
            GetNameByOffset(FastIo->MdlWriteComplete, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoReadCompressed)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoReadCompressed",
            FastIo->FastIoReadCompressed,
            IsPointerHooked(FastIo->FastIoReadCompressed) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoReadCompressed, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoWriteCompressed)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoWriteCompressed",
            FastIo->FastIoWriteCompressed,
            IsPointerHooked(FastIo->FastIoWriteCompressed) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoWriteCompressed, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlReadCompleteCompressed)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "MdlReadCompleteCompressed",
            FastIo->MdlReadCompleteCompressed,
            IsPointerHooked(FastIo->MdlReadCompleteCompressed) ? "Hooked" : "",
            GetNameByOffset(FastIo->MdlReadCompleteCompressed, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->MdlWriteCompleteCompressed)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "MdlWriteCompleteCompressed",
            FastIo->MdlWriteCompleteCompressed,
            IsPointerHooked(FastIo->MdlWriteCompleteCompressed) ? "Hooked" : "",
            GetNameByOffset(FastIo->MdlWriteCompleteCompressed, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->FastIoQueryOpen)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "FastIoQueryOpen",
            FastIo->FastIoQueryOpen,
            IsPointerHooked(FastIo->FastIoQueryOpen) ? "Hooked" : "",
            GetNameByOffset(FastIo->FastIoQueryOpen, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->ReleaseForModWrite)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "ReleaseForModWrite",
            FastIo->ReleaseForModWrite,
            IsPointerHooked(FastIo->ReleaseForModWrite) ? "Hooked" : "",
            GetNameByOffset(FastIo->ReleaseForModWrite, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->AcquireForCcFlush)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "AcquireForCcFlush",
            FastIo->AcquireForCcFlush,
            IsPointerHooked(FastIo->AcquireForCcFlush) ? "Hooked" : "",
            GetNameByOffset(FastIo->AcquireForCcFlush, (LPSTR)Name, _countof(Name)));
    }

    if (FastIo->ReleaseForCcFlush)
    {
        g_Ext->Dml("    \\---| %-32s | 0x%I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            "ReleaseForCcFlush",
            FastIo->ReleaseForCcFlush,
            IsPointerHooked(FastIo->ReleaseForCcFlush) ? "Hooked" : "",
            GetNameByOffset(FastIo->ReleaseForCcFlush, (LPSTR)Name, _countof(Name)));
    }
}