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

    - System.cpp

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"

//
// SSDT
// IDT
// GDT
// KTIMER
// Objects
// Drivers
// -> Callbacks
//

vector<SSDT_ENTRY>
GetServiceDescriptorTable(
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    vector<SSDT_ENTRY>.

--*/
{
    vector<SSDT_ENTRY> SDT;
    IMAGE_NT_HEADERS64 ImageNtHeaders;
    ULONG64 KiServiceTable;
    ULONG64 Address;
    ULONG64 ServiceAddress;
    ULONG64 KernelBase = NULL;
    ULONG64 KernelEnd = NULL;
    ULONG Limit;
    BOOLEAN Status = FALSE;

    ReadPointer(GetExpression("nt!KeServiceDescriptorTable"), &KiServiceTable);
    if (g_Ext->m_Data->ReadVirtual(GetExpression("nt!KiServiceLimit"), &Limit, sizeof(ULONG), NULL) != S_OK) goto Exit;

    if (!KiServiceTable) goto Exit;

    KernelBase = ExtNtOsInformation::GetNtDebuggerData(DEBUG_DATA_KernBase, "nt", 0);

    if (KernelBase) {

        g_Ext->m_Data4->ReadImageNtHeaders(KernelBase, &ImageNtHeaders);

        KernelEnd = KernelBase + ImageNtHeaders.OptionalHeader.SizeOfImage;
    }

    Address = KiServiceTable;

    if (g_Ext->m_ActualMachine == IMAGE_FILE_MACHINE_I386) {

        for (UINT i = 0; i < Limit; i++, Address += sizeof(ULONG)) {

            SSDT_ENTRY Entry = {0};

            ReadPointer(Address, &ServiceAddress);
            if (!ServiceAddress) break;

            Entry.Index = i;
            Entry.Address.Address = ServiceAddress;
            Entry.Address.IsHooked = IsPointerHooked(ServiceAddress);

            if ((KernelBase && KernelEnd) && !(ServiceAddress >= KernelBase && ServiceAddress < KernelEnd)) {

                Entry.Address.IsTablePatched = TRUE;
            }

            SDT.push_back(Entry);
        }
    }
    else {

        LONG Offset;

        for (UINT i = 0; i < Limit; i++, Address += sizeof(ULONG)) {

            SSDT_ENTRY Entry = {0};

            if (g_Ext->m_Data->ReadVirtual(Address, &Offset, sizeof(Offset), NULL) != S_OK) break;

            if (g_Ext->m_Minor < 6000) Offset &= ~0xF;
            else Offset >>= 4;

            ServiceAddress = KiServiceTable + Offset;

            Entry.Index = i;
            Entry.Address.Address = ServiceAddress;
            Entry.Address.IsHooked = IsPointerHooked(ServiceAddress);

            if ((KernelBase && KernelEnd) && !(ServiceAddress >= KernelBase && ServiceAddress < KernelEnd)) {

                Entry.Address.IsTablePatched = TRUE;
            }

            SDT.push_back(Entry);
        }
    }

    Status = TRUE;

Exit:
    return SDT;
}

vector<SERVICE_ENTRY>
GetServices(
    VOID
    )
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    vector<SERVICE_ENTRY>.

--*/
{
    MsProcessObject ProcessObject = FindProcessByName("services.exe");
    vector<SERVICE_ENTRY> Services;
    SERVICE_ENTRY ServiceEntry;
    ULONG64 RangeStart;
    ULONG64 RangeEnd;
    ULONG64 Offset;
    PULONG Buffer;
    ULONG BufferSize;

    if (!ProcessObject.m_CcProcessObject.ProcessObjectPtr) {

        return Services;
    }

    BufferSize = g_Ext->m_PageSize ? g_Ext->m_PageSize : PAGE_SIZE;

    Buffer = (PULONG)calloc(BufferSize * 2, sizeof(BYTE));

    if (Buffer) {

        ProcessObject.SwitchContext();

        g_Ext->Execute(".process /p /r 0x%I64X", ProcessObject.m_CcProcessObject.ProcessObjectPtr);

        ProcessObject.MmGetVads();

        if (g_Ext->m_ActualMachine == IMAGE_FILE_MACHINE_I386) {

            for each (VAD_OBJECT Vad in ProcessObject.m_Vads) {

                if (Vad.PrivateMemory) {

                    RangeStart = Vad.StartingVpn * BufferSize;
                    RangeEnd = Vad.EndingVpn * BufferSize;

                    for (Offset = RangeStart; Offset < RangeEnd; Offset += BufferSize) {

                        RtlZeroMemory(Buffer, BufferSize);

                        if (ExtRemoteTypedEx::ReadVirtual(Offset, Buffer, BufferSize, NULL) != S_OK) {

                            continue;
                        }

                        for (UINT i = 0; i < (BufferSize / sizeof(ULONG)); i += 1) {

                            if (Buffer[i] == SERVICE_SIGNATURE_NT6) {

                                PSERVICE_HANDLE_X86 ServiceHandle = (PSERVICE_HANDLE_X86)(&Buffer[i]);
                                SERVICE_RECORD_X86 ServiceRecord;
                                IMAGE_RECORD_X86 ImageRecord;

                                RtlZeroMemory(&ServiceEntry, sizeof(ServiceEntry));

                                if (ExtRemoteTypedEx::ReadVirtual(ServiceHandle->ServiceRecord, &ServiceRecord, sizeof(ServiceRecord), NULL) != S_OK) {

                                    continue;
                                }

                                if (!IsValid((ULONG64)ServiceRecord.ServiceName) ||
                                    !IsValid((ULONG64)ServiceRecord.DisplayName)) {

                                    continue;
                                }

                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord.ServiceName, ServiceEntry.Name, sizeof(ServiceEntry.Name));
                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord.DisplayName, ServiceEntry.Desc, sizeof(ServiceEntry.Desc));

                                ServiceEntry.StartType = ServiceRecord.StartType;
                                ServiceEntry.ServiceStatus = ServiceRecord.ServiceStatus;
                                ServiceEntry.UseCount = ServiceRecord.UseCount;

                                if ((ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_OWN_PROCESS) ||
                                    (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_SHARE_PROCESS)) {

                                    if (ExtRemoteTypedEx::ReadVirtual(ServiceRecord.ImageRecord, &ImageRecord, sizeof(ImageRecord), NULL) != S_OK) {

                                        continue;
                                    }

                                    ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.ImageName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));

                                    ServiceEntry.ProcessHandle = (ULONG64)ImageRecord.ProcessHandle;
                                    ServiceEntry.ProcessId = ImageRecord.Pid;
                                    ServiceEntry.TokenHandle = (ULONG64)ImageRecord.TokenHandle;

                                    /* if (IsValid((ULONG64)ImageRecord.AccountName))
                                    {
                                    // ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.AccountName, (LPSTR)ServiceEntry.AccountName, sizeof(ServiceEntry.AccountName));
                                    }*/
                                    ServiceEntry.ServiceCount = ImageRecord.ServiceCount;
                                }
                                else if (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_KERNEL_DRIVER) {

                                    ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord.ObjectName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));
                                }

                                Services.push_back(ServiceEntry);
                            }
                            else if (Buffer[i] == SERVICE_SIGNATURE_NT5) {

                                PUCHAR pServiceRecord = (PUCHAR)(&Buffer[i]);
                                PSERVICE_RECORD_X86 ServiceRecord;
                                IMAGE_RECORD_X86 ImageRecord;

                                RtlZeroMemory(&ServiceEntry, sizeof(ServiceEntry));

                                pServiceRecord -= FIELD_OFFSET(SERVICE_RECORD_X86, UseCount);
                                ServiceRecord = (PSERVICE_RECORD_X86)pServiceRecord;

                                if (!IsValid((ULONG64)ServiceRecord->ServiceName) ||
                                    !IsValid((ULONG64)ServiceRecord->DisplayName)) {

                                    continue;
                                }

                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord->ServiceName, ServiceEntry.Name, sizeof(ServiceEntry.Name));
                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord->DisplayName, ServiceEntry.Desc, sizeof(ServiceEntry.Desc));

                                ServiceRecord = (PSERVICE_RECORD_X86)(pServiceRecord + sizeof(ULONG)); // shift of one DWORD, because NT5 do use Signature.

                                ServiceEntry.StartType = ServiceRecord->StartType;
                                ServiceEntry.ServiceStatus = ServiceRecord->ServiceStatus;
                                ServiceEntry.UseCount = ServiceRecord->UseCount;

                                if ((ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_OWN_PROCESS) ||
                                    (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_SHARE_PROCESS)) {

                                    if (ExtRemoteTypedEx::ReadVirtual(ServiceRecord->ImageRecord, &ImageRecord, sizeof(ImageRecord), NULL) != S_OK) {

                                        continue;
                                    }

                                    ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.ImageName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));

                                    ServiceEntry.ProcessHandle = (ULONG64)ImageRecord.ProcessHandle;
                                    ServiceEntry.ProcessId = ImageRecord.Pid;
                                    ServiceEntry.TokenHandle = (ULONG64)ImageRecord.TokenHandle;

                                    /* if (IsValid((ULONG64)ImageRecord.AccountName))
                                    {
                                    // ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.AccountName, ServiceEntry.AccountName, sizeof(ServiceEntry.AccountName));
                                    }*/

                                    ServiceEntry.ServiceCount = ImageRecord.ServiceCount;
                                }
                                else if (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_KERNEL_DRIVER) {

                                    ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord->ObjectName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));
                                }

                                Services.push_back(ServiceEntry);
                            }
                        }
                    }
                }
            }
        }
        else {

            for each (VAD_OBJECT Vad in ProcessObject.m_Vads) {

                if (Vad.PrivateMemory) {

                    RangeStart = Vad.StartingVpn * BufferSize;
                    RangeEnd = Vad.EndingVpn * BufferSize;

                    for (Offset = RangeStart; Offset < RangeEnd; Offset += BufferSize) {

                        RtlZeroMemory(Buffer, BufferSize);

                        if (ExtRemoteTypedEx::ReadVirtual(Offset, Buffer, BufferSize, NULL) != S_OK) {

                            continue;
                        }

                        for (UINT i = 0; i < (BufferSize / sizeof(ULONG)); i += 1) {

                            if (Buffer[i] == SERVICE_SIGNATURE_NT6) {

                                PSERVICE_HANDLE_X64 ServiceHandle = (PSERVICE_HANDLE_X64)(&Buffer[i]);
                                SERVICE_RECORD_X64 ServiceRecord;
                                IMAGE_RECORD_X64 ImageRecord;

                                RtlZeroMemory(&ServiceEntry, sizeof(ServiceEntry));

                                if (ExtRemoteTypedEx::ReadVirtual(ServiceHandle->ServiceRecord, &ServiceRecord, sizeof(ServiceRecord), NULL) != S_OK) {

                                    continue;
                                }

                                if (!IsValid((ULONG64)ServiceRecord.ServiceName) ||
                                    !IsValid((ULONG64)ServiceRecord.DisplayName)) {

                                    continue;
                                }

                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord.ServiceName, ServiceEntry.Name, sizeof(ServiceEntry.Name));
                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord.DisplayName, ServiceEntry.Desc, sizeof(ServiceEntry.Desc));

                                ServiceEntry.StartType = ServiceRecord.StartType;
                                ServiceEntry.ServiceStatus = ServiceRecord.ServiceStatus;
                                ServiceEntry.UseCount = ServiceRecord.UseCount;

                                if ((ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_OWN_PROCESS) ||
                                    (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_SHARE_PROCESS)) {

                                    if (ExtRemoteTypedEx::ReadVirtual(ServiceRecord.ImageRecord, &ImageRecord, sizeof(ImageRecord), NULL) != S_OK) {

                                        continue;
                                    }

                                    ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.ImageName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));

                                    ServiceEntry.ProcessHandle = (ULONG64)ImageRecord.ProcessHandle;
                                    ServiceEntry.ProcessId = ImageRecord.Pid;
                                    ServiceEntry.TokenHandle = (ULONG64)ImageRecord.TokenHandle;

                                    /* if (IsValid((ULONG64)ImageRecord.AccountName))
                                    {
                                    // ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.AccountName, (LPSTR)ServiceEntry.AccountName, sizeof(ServiceEntry.AccountName));
                                    }*/

                                    ServiceEntry.ServiceCount = ImageRecord.ServiceCount;
                                }
                                else if (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_KERNEL_DRIVER) {

                                    ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord.ObjectName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));
                                }

                                Services.push_back(ServiceEntry);
                            }
                            else if (Buffer[i] == SERVICE_SIGNATURE_NT5) {

                                PUCHAR pServiceRecord = (PUCHAR)(&Buffer[i]);
                                PSERVICE_RECORD_X64 ServiceRecord = NULL;
                                IMAGE_RECORD_X64 ImageRecord;

                                RtlZeroMemory(&ServiceEntry, sizeof(ServiceEntry));

                                pServiceRecord -= FIELD_OFFSET(SERVICE_RECORD_X64, UseCount);
                                ServiceRecord = (PSERVICE_RECORD_X64)pServiceRecord;

                                if (!IsValid((ULONG64)ServiceRecord->ServiceName) ||
                                    !IsValid((ULONG64)ServiceRecord->DisplayName)) {

                                    continue;
                                }

                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord->ServiceName, ServiceEntry.Name, sizeof(ServiceEntry.Name));
                                ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord->DisplayName, ServiceEntry.Desc, sizeof(ServiceEntry.Desc));

                                ServiceRecord = (PSERVICE_RECORD_X64)(pServiceRecord + sizeof(ULONG)); // shift of one DWORD, because NT5 do use Signature.

                                ServiceEntry.StartType = ServiceRecord->StartType;
                                ServiceEntry.ServiceStatus = ServiceRecord->ServiceStatus;
                                ServiceEntry.UseCount = ServiceRecord->UseCount;

                                if ((ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_OWN_PROCESS) ||
                                    (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_SHARE_PROCESS)) {

                                    if (ExtRemoteTypedEx::ReadVirtual(ServiceRecord->ImageRecord, &ImageRecord, sizeof(ImageRecord), NULL) != S_OK) {

                                        continue;
                                    }

                                    ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.ImageName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));

                                    ServiceEntry.ProcessHandle = (ULONG64)ImageRecord.ProcessHandle;
                                    ServiceEntry.ProcessId = ImageRecord.Pid;
                                    ServiceEntry.TokenHandle = (ULONG64)ImageRecord.TokenHandle;

                                    // ExtRemoteTypedEx::GetString((ULONG64)ImageRecord.AccountName, (LPSTR)ServiceEntry.AccountName, sizeof(ServiceEntry.AccountName));
                                    ServiceEntry.ServiceCount = ImageRecord.ServiceCount;
                                }
                                else if (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_KERNEL_DRIVER) {

                                    ExtRemoteTypedEx::GetString((ULONG64)ServiceRecord->ObjectName, ServiceEntry.CommandLine, sizeof(ServiceEntry.CommandLine));
                                }

                                Services.push_back(ServiceEntry);
                            }
                        }
                    }
                }
            }
        }

        ProcessObject.RestoreContext();

        free(Buffer);
    }

    return Services;
}

PSTR
GetPartitionType(
    _In_ ULONG Type
)
/*++

Routine Description:

    Description.

Arguments:

    Type -

Return Value:

    LPSTR.

--*/
{
    switch (Type)
    {
        case 0x00: return "Empty"; break;
        case 0x01: return "FAT12; break;CHS"; break;
        case 0x04: return "FAT16 16-32MB; break;CHS"; break;
        case 0x05: return "Microsoft Extended"; break;
        case 0x06: return "FAT16 32MB; break;CHS"; break;
        case 0x07: return "NTFS"; break;
        case 0x0b: return "FAT32; break;CHS"; break;
        case 0x0c: return "FAT32; break;LBA"; break;
        case 0x0e: return "FAT16; break; 32MB-2GB; break;LBA"; break;
        case 0x0f: return "Microsoft Extended; break; LBA"; break;
        case 0x11: return "Hidden FAT12; break;CHS"; break;
        case 0x14: return "Hidden FAT16; break;16-32MB; break;CHS"; break;
        case 0x16: return "Hidden FAT16; break;32MB-2GB; break;CHS"; break;
        case 0x18: return "AST SmartSleep Partition"; break;
        case 0x1b: return "Hidden FAT32; break;CHS"; break;
        case 0x1c: return "Hidden FAT32; break;LBA"; break;
        case 0x1e: return "Hidden FAT16; break;32MB-2GB; break;LBA"; break;
        case 0x27: return "PQservice"; break;
        case 0x39: return "Plan 9 partition"; break;
        case 0x3c: return "PartitionMagic recovery partition"; break;
        case 0x42: return "Microsoft MBR; break;Dynamic Disk"; break;
        case 0x44: return "GoBack partition"; break;
        case 0x51: return "Novell"; break;
        case 0x52: return "CP/M"; break;
        case 0x63: return "Unix System V"; break;
        case 0x64: return "PC-ARMOUR protected partition"; break;
        case 0x82: return "Solaris x86 or Linux Swap"; break;
        case 0x83: return "Linux"; break;
        case 0x84: return "Hibernation"; break;
        case 0x85: return "Linux Extended"; break;
        case 0x86: return "NTFS Volume Set"; break;
        case 0x87: return "NTFS Volume Set"; break;
        case 0x9f: return "BSD/OS"; break;
        case 0xa0: return "Hibernation"; break;
        case 0xa1: return "Hibernation"; break;
        case 0xa5: return "FreeBSD"; break;
        case 0xa6: return "OpenBSD"; break;
        case 0xa8: return "Mac OSX"; break;
        case 0xa9: return "NetBSD"; break;
        case 0xab: return "Mac OSX Boot"; break;
        case 0xaf: return "MacOS X HFS"; break;
        case 0xb7: return "BSDI"; break;
        case 0xb8: return "BSDI Swap"; break;
        case 0xbb: return "Boot Wizard hidden"; break;
        case 0xbe: return "Solaris 8 boot partition"; break;
        case 0xd8: return "CP/M-86"; break;
        case 0xde: return "Dell PowerEdge Server utilities (FAT fs)"; break;
        case 0xdf: return "DG/UX virtual disk manager partition"; break;
        case 0xeb: return "BeOS BFS"; break;
        case 0xee: return "EFI GPT Disk"; break;
        case 0xef: return "EFI System Parition"; break;
        case 0xfb: return "VMWare File System"; break;
        case 0xfc: return "VMWare Swap"; break;
    }

    return "Unknown";
}

ULONG64
KiDecodePointer(
    _In_ ULONG64 Pointer,
    _In_ ULONG64 Salt
)
/*++

Routine Description:

    Description.

Arguments:

    Pointer -
    Salt - 

Return Value:

    ULONG64.

--*/
{
    ULONG64 Value = (ULONG64)Pointer;

    // g_Ext->Dml("in => 0x%I64X\n", Pointer);

    if (g_Ext->IsCurMachine64())
    {
        ULONG64 Bias = (ULONG64)Salt;
        ULONG64 KiWaitNever = GetExpression("nt!KiWaitNever");
        ULONG64 KiWaitAlways = GetExpression("nt!KiWaitAlways");

        // g_Ext->Dml("KiWaitNever = %I64X | KiWaitAlways = %I64X\n", KiWaitNever, KiWaitAlways);

        ReadPointer(KiWaitNever, &KiWaitNever);
        ReadPointer(KiWaitAlways, &KiWaitAlways);

        Value = RotateLeft64(Value ^ KiWaitNever, (int)KiWaitNever);
        Value = _byteswap_uint64(Value ^ Bias) ^ KiWaitAlways;
    }

    return Value;
}

vector<KTIMER>
GetTimers(
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    vector<KTIMER>.

--*/
{
    vector<KTIMER> Timers;
    ULONG KeNumberProcessors;
    PULONG64 KiProcessorBlock;

    ULONG64 KiTimerTableListHead = GetExpression("nt!KiTimerTableListHead");
    vector<ULONG64> ReadedTimers(1024);

    if (KiTimerTableListHead)
    {
        ExtRemoteTyped TimerTable;
        ExtRemoteUnTyped UntypedTimerTable;
        ULONG MaxEntries = 256; // default

        TimerTable = ExtRemoteTyped("(nt!_LIST_ENTRY *)@$extin", KiTimerTableListHead);

        // ULONG MaxEntries = GetTypeSize("nt!KiTimerTableListHead") / KTimerEntrySize;
        // g_Ext->Dml("MaxEntries = %d / TimerTableListSize = %x\n", MaxEntries, GetTypeSize("nt!KiTimerTableListHead"));

        if (g_Ext->m_Minor < 3790) MaxEntries = 256;// XP x86 and Win2003 SP0
        else if ((g_Ext->m_Minor >= 3790) && (g_Ext->m_Minor < 7600)) MaxEntries = 512; // XP x64, Vista
        else
        {
            g_Ext->Dml("Unsupported version for ktimers. (%d)\n", g_Ext->m_Minor);
        }

        for (UINT i = 0; i < MaxEntries; i += 1)
        {
            ULONG64 FirstEntry;

            FirstEntry = TimerTable.ArrayElement(i).Field("Flink").GetPointerTo().GetPtr();
            if (!FirstEntry) continue;

            if (!IsValid(FirstEntry)) continue;

            ExtRemoteTypedList TimerList(FirstEntry, "nt!_KTIMER", "TimerListEntry");

            for (TimerList.StartHead(); TimerList.HasNode(); TimerList.Next())
            {
                KTIMER Timer = { 0 };

                ULONG64 Ptr = TimerList.GetTypedNode().GetPointerTo().GetPtr();

                BOOLEAN Found = FALSE;
                for each (ULONG64 Current in ReadedTimers)
                {
                    if (Current == Ptr)
                    {
                        Found = TRUE;
                        break;
                    }
                }
                if (Found) break;
                ReadedTimers.push_back(Ptr);

                UCHAR Type = TimerList.GetTypedNode().Field("Header.Type").GetUchar();
                if ((Type != TimerNotificationObject) && (Type != TimerSynchronizationObject)) continue;
                Timer.Type = Type;

                Timer.Timer = Ptr;
                Timer.Dpc = TimerList.GetTypedNode().Field("Dpc").GetPtr();

                Timer.DueTime.HighPart = TimerList.GetTypedNode().Field("DueTime.HighPart").GetUlong();
                Timer.DueTime.LowPart = TimerList.GetTypedNode().Field("DueTime.LowPart").GetUlong();

                Timer.Period = TimerList.GetTypedNode().Field("Period").GetUlong();

                if (IsValid(Timer.Dpc))
                {
                    Timer.DeferredRoutine = TimerList.GetTypedNode().Field("Dpc").Field("DeferredRoutine").GetPtr();
                }

                Timers.push_back(Timer);
            }
        }
    }
    else
    {
        if (g_Ext->m_Data->ReadVirtual(GetExpression("nt!KeNumberProcessors"), &KeNumberProcessors, sizeof(KeNumberProcessors), NULL) != S_OK) goto CleanUp;

        KiProcessorBlock = (PULONG64)malloc(KeNumberProcessors * sizeof(ULONG64));
        if (!KiProcessorBlock) goto CleanUp;

        if (ReadPointersVirtual(KeNumberProcessors, GetExpression("nt!KiProcessorBlock"), KiProcessorBlock) != S_OK) goto CleanUp;

        for (UINT i = 0; KiProcessorBlock[i] && (i < KeNumberProcessors); i += 1)
        {
            ULONG MaxEntries = 0;
            ExtRemoteTyped Pcr("(nt!_KPCR *)@$extin", KiProcessorBlock[i]);

            MaxEntries = Pcr.Field("Prcb.TimerTable.TimerEntries").GetTypeSize() / GetTypeSize("nt!_KTIMER_TABLE_ENTRY");
            // g_Ext->Dml("MaxEntries = %d\n", MaxEntries);

            for (UINT j = 0; j < MaxEntries; j += 1)
            {
                ULONG64 ListHead;

                if (Pcr.HasField("PrcbData"))
                {
                    ListHead = Pcr.Field("PrcbData.TimerTable.TimerEntries").ArrayElement(j).Field("Entry.Flink").GetPtr();
                }
                else
                {
                    ListHead = Pcr.Field("Prcb.TimerTable.TimerEntries").ArrayElement(j).Field("Entry.Flink").GetPtr();
                }
                // g_Ext->Dml("[%d][%d] ListHead =%I64X\n", i, j, ListHead);
                if (!ListHead) continue;
                if (!IsValid(ListHead)) continue;

                ExtRemoteTypedList TimerList(ListHead, "nt!_KTIMER", "TimerListEntry");

                for (TimerList.StartHead(); TimerList.HasNode(); TimerList.Next())
                {
                    KTIMER Timer = { 0 };
                    ULONG64 Ptr = TimerList.GetTypedNode().GetPointerTo().GetPtr();

                    // g_Ext->Dml("[%d][%d] KTIMER @ 0x%I64X (%s) (ListHead = 0x%I64X)\n", i, j, Ptr, IsValid(Ptr) ? "Valid" : "Error", ListHead);
                    if (!IsValid(Ptr)) break;

                    BOOLEAN Found = FALSE;
                    for each (ULONG64 Current in ReadedTimers)
                    {
                        if (Current == Ptr)
                        {
                            Found = TRUE;
                            break;
                        }
                    }
                    if (Found) break;
                    ReadedTimers.push_back(Ptr);

                    UCHAR Type = TimerList.GetTypedNode().Field("Header.Type").GetUchar();
                    if ((Type != TimerNotificationObject) && (Type != TimerSynchronizationObject)) continue;

                    Timer.Type = Type;

                    Timer.CoreId = i;
                    Timer.Timer = Ptr;
                    Timer.Dpc = TimerList.GetTypedNode().Field("Dpc").GetPtr();

                    Timer.Dpc = KiDecodePointer(Timer.Dpc, Timer.Timer);
                    // g_Ext->Dml("Timer.Timer = %I64X Timer.Dpc = %I64X\n", Timer.Timer, Timer.Dpc);

                    Timer.DueTime.HighPart = TimerList.GetTypedNode().Field("DueTime.HighPart").GetUlong();
                    Timer.DueTime.LowPart = TimerList.GetTypedNode().Field("DueTime.LowPart").GetUlong();

                    Timer.Period = TimerList.GetTypedNode().Field("Period").GetUlong();

                    if (IsValid(Timer.Dpc))
                    {
                        ExtRemoteTyped Dpc("(nt!_KDPC *)@$extin", Timer.Dpc);
                        ULONG DpcType = Dpc.Field("Type").GetUchar();

                        if ((DpcType == ApcObject) || (DpcType == DpcObject))
                        {
                            //Dpc.OutFullValue();
                            Timer.DpcType = DpcType;
                            Timer.DeferredRoutine = Dpc.Field("DeferredRoutine").GetPtr();
                        }
                    }

                    Timers.push_back(Timer);
                }

                //g_Ext->Dml("Done\n");
            }
            //g_Ext->Dml("Core done\n");
        }
    }

CleanUp:
    return Timers;
}

vector<VACB_OBJECT>
GetVacbs(
)
/*++

Routine Description:

    Description.

Arguments:

    -

Return Value:

    vector<VACB_OBJECT>.

--*/
{
    vector<VACB_OBJECT> Vacbs;

    ULONG64 VacbArrayBase = GetExpression("nt!CcVacbArrays");
    ULONG64 pData;
    ULONG CcVacbArraysHighestUsedIndex;
    PULONG64 VacbArray = NULL;

    vector<ULONG64> ReadedVacbs(1024);

    if (!VacbArrayBase) goto CleanUp;
    ReadPointer(VacbArrayBase, &VacbArrayBase);
    ReadPointer(GetExpression("nt!CcVacbArraysHighestUsedIndex"), &pData);

    CcVacbArraysHighestUsedIndex = (ULONG)pData;

    // g_Ext->Dml("CcVacbArraysHighestUsedIndex = %d\n", CcVacbArraysHighestUsedIndex);

    VacbArray = (PULONG64)malloc(CcVacbArraysHighestUsedIndex * sizeof(ULONG64));
    if (VacbArray == NULL) goto CleanUp;

    // g_Ext->Dml("VacbArrayBase = %I64X\n", VacbArrayBase);
    if (ReadPointersVirtual(CcVacbArraysHighestUsedIndex, VacbArrayBase, VacbArray) != S_OK) goto CleanUp;

    for (UINT VacbIndex = 0; VacbIndex < CcVacbArraysHighestUsedIndex; VacbIndex += 1)
    {
        ULONG VacbArrayHeaderSize = GetTypeSize("nt!_VACB_ARRAY_HEADER");

        // g_Ext->Dml("VacbArray[%d] = 0x%I64X\n", VacbIndex, VacbArray[VacbIndex]);
        ExtRemoteTyped Vacb("(nt!_VACB *)@$extin", VacbArray[VacbIndex] + VacbArrayHeaderSize);

        ULONG64 ListHead = Vacb.Field("Links.Flink").GetPointerTo().GetPtr();
        ExtRemoteTypedList VacbList(ListHead, "nt!_VACB", "Links.Flink");

        for (VacbList.StartHead(); VacbList.HasNode(); VacbList.Next())
        {
            for each (ULONG64 Ptr in ReadedVacbs)
            {
                if (Ptr == VacbList.GetNodeOffset()) goto CleanUp;
            }

            ReadedVacbs.push_back(VacbList.GetNodeOffset());

            ULONG64 BaseAddress = VacbList.GetTypedNode().Field("BaseAddress").GetPtr();
            ULONG64 SharedCacheMap = VacbList.GetTypedNode().Field("SharedCacheMap").GetPtr();

            if (BaseAddress || SharedCacheMap)
            {
                VACB_OBJECT VacbObject = { 0 };

                // VacbList.GetTypedNode().OutFullValue();
                VacbObject.Vacb = VacbList.GetNodeOffset();
                VacbObject.BaseAddress = BaseAddress;
                VacbObject.ValidBase = IsValid(BaseAddress);
                VacbObject.SharedCacheMap = SharedCacheMap;

                Vacbs.push_back(VacbObject);
            }
        }
    }

CleanUp:
    if (VacbArray) free(VacbArray);

    return Vacbs;
}

vector<IDT_OBJECT>
GetInterrupts(
    _In_opt_ ULONG64 InIdtBase
)
/*++

Routine Description:

    Description.

Arguments:

    InIdtBase -

Return Value:

    vector<IDT_OBJECT>.

--*/
{
    vector<IDT_OBJECT> Idts;
    ULONG KeNumberProcessors;
    PULONG64 KiProcessorBlock;

    vector<ULONG64> IdtBases;

    if (!InIdtBase)
    {
        if (g_Ext->m_Data->ReadVirtual(GetExpression("nt!KeNumberProcessors"), &KeNumberProcessors, sizeof(KeNumberProcessors), NULL) != S_OK) goto CleanUp;

        KiProcessorBlock = (PULONG64)malloc(KeNumberProcessors * sizeof(ULONG64));
        if (!KiProcessorBlock) goto CleanUp;

        if (ReadPointersVirtual(KeNumberProcessors, GetExpression("nt!KiProcessorBlock"), KiProcessorBlock) != S_OK) goto CleanUp;

        ULONG PrcbOffset = 0;

        if (GetFieldOffset("nt!_KPCR", "PrcbData", &PrcbOffset) != S_OK) GetFieldOffset("nt!_KPCR", "Prcb", &PrcbOffset);

        for (UINT i = 0; KiProcessorBlock[i] && (i < KeNumberProcessors); i += 1)
        {
            ULONG64 IdtBase;
            ULONG IdtOffset;
            ExtRemoteTyped Pcr("(nt!_KPCR *)@$extin", (ULONG64)KiProcessorBlock[i] - PrcbOffset);

            // g_Ext->Dml("KPCR = %I64X offset = %x\n", KiProcessorBlock[i], PrcbOffset);
            // Pcr.OutFullValue();

            if (GetFieldOffset("nt!_KPCR", "IdtBase", &IdtOffset) != S_OK) GetFieldOffset("nt!_KPCR", "IDT", &IdtOffset);

            ReadPointer(KiProcessorBlock[i] - PrcbOffset + IdtOffset, &IdtBase);

            // if (Pcr.HasField("IdtBase")) IdtBase = Pcr.Field("IdtBase").GetPtr();
            // else if (Pcr.HasField("IDT")) IdtBase = Pcr.Field("IDT").GetPtr();

            if (!IdtBase) continue;

            IdtBases.push_back(IdtBase);
        }
    }
    else
    {
        IdtBases.push_back(InIdtBase);
    }

    UINT i = 0;
    for each (ULONG64 IdtBase in IdtBases)
    {
        if (g_Ext->m_ActualMachine == IMAGE_FILE_MACHINE_I386)
        {
            IDT_OBJECT IdtEntry = { 0 };
            ExtRemoteTyped Idt("(nt!_KIDTENTRY *)@$extin", IdtBase);

            for (UINT j = 0; j < 256; j += 1)
            {
                ULONG64 Entry = (Idt.ArrayElement(j).Field("ExtendedOffset").GetUshort() << 16) |
                    (Idt.ArrayElement(j).Field("Offset").GetUshort());

                IdtEntry.Entry = Entry;
                IdtEntry.Index = j;
                IdtEntry.CoreIndex = i;

                Idts.push_back(IdtEntry);
            }
        }
        else
        {
            for (UINT j = 0; j < 256; j += 1)
            {
                KIDTENTRY64 IdtEntry64 = { 0 };
                IDT_OBJECT IdtEntry = { 0 };

                if (g_Ext->m_Data->ReadVirtual(IdtBase + j * sizeof(KIDTENTRY64),
                                               &IdtEntry64,
                                               sizeof(IdtEntry64), NULL) != S_OK) goto CleanUp;

                ULONG64 Entry = IdtEntry64.OffsetHigh;
                Entry <<= 32;
                Entry |= IdtEntry64.OffsetMiddle << 16;
                Entry |= IdtEntry64.OffsetLow;

                IdtEntry.Entry = Entry;
                IdtEntry.Dpl = IdtEntry64.Dpl;
                IdtEntry.Present = IdtEntry64.Present;
                IdtEntry.Type = IdtEntry64.Type;

                IdtEntry.Index = j;
                IdtEntry.CoreIndex = i;

                Idts.push_back(IdtEntry);
            }
        }

        i += 1;
    }

CleanUp:
    return Idts;
}

vector<GDT_OBJECT>
GetDescriptors(
    _In_opt_ ULONG64 InGdtBase
)
/*++

Routine Description:

    Description.

Arguments:

    InGdtBase

Return Value:

    vector<GDT_OBJECT>.

--*/
{
    vector<GDT_OBJECT> Gdts;
    ULONG KeNumberProcessors;
    PULONG64 KiProcessorBlock;

    vector<ULONG64> GdtBases;

    if (!InGdtBase)
    {
        if (g_Ext->m_Data->ReadVirtual(GetExpression("nt!KeNumberProcessors"), &KeNumberProcessors, sizeof(KeNumberProcessors), NULL) != S_OK) goto CleanUp;

        KiProcessorBlock = (PULONG64)malloc(KeNumberProcessors * sizeof(ULONG64));
        if (!KiProcessorBlock) goto CleanUp;

        if (ReadPointersVirtual(KeNumberProcessors, GetExpression("nt!KiProcessorBlock"), KiProcessorBlock) != S_OK) goto CleanUp;

        ULONG PrcbOffset;

        if (GetFieldOffset("nt!_KPCR", "PrcbData", &PrcbOffset) != S_OK) GetFieldOffset("nt!_KPCR", "Prcb", &PrcbOffset);

        for (UINT i = 0; KiProcessorBlock[i] && (i < KeNumberProcessors); i += 1)
        {
            ULONG64 GdtBase;
            ULONG GdtOffset;

            ExtRemoteTyped Pcr("(nt!_KPCR *)@$extin", KiProcessorBlock[i] - PrcbOffset);

            // if (Pcr.HasField("GdtBase")) GdtBase = Pcr.Field("GdtBase").GetPtr();
            // else if (Pcr.HasField("GDT")) GdtBase = Pcr.Field("GDT").GetPtr();

            if (GetFieldOffset("nt!_KPCR", "GdtBase", &GdtOffset) != S_OK) GetFieldOffset("nt!_KPCR", "GDT", &GdtOffset);

            ReadPointer(KiProcessorBlock[i] - PrcbOffset + GdtOffset, &GdtBase);

            if (!GdtBase) continue;

            GdtBases.push_back(GdtBase);
        }
    }
    else
    {
        GdtBases.push_back(InGdtBase);
    }

    UINT i = 0;
    for each (ULONG64 GdtBase in GdtBases)
    {
        if (g_Ext->m_ActualMachine == IMAGE_FILE_MACHINE_I386)
        {
            ExtRemoteTyped Gdt("(nt!_KGDTENTRY *)@$extin", GdtBase);
            ULONG64 Entry = 0;

            for (UINT j = 0; j < 256; j += 1)
            {
                GDT_OBJECT GdtEntry = { 0 };
                Entry = (Gdt.ArrayElement(j).Field("HighWord.Bytes.BaseHi").GetUchar() << 24) |
                                (Gdt.ArrayElement(j).Field("HighWord.Bytes.BaseMid").GetUchar() << 16) |
                                (Gdt.ArrayElement(j).Field("BaseLow").GetUshort());
                GdtEntry.Limit = (Gdt.ArrayElement(j).Field("HighWord.Bits.LimitHi").GetUlong() << 16) |
                                 (Gdt.ArrayElement(j).Field("LimitLow").GetUshort());

                GdtEntry.Dpl = Gdt.ArrayElement(j).Field("HighWord.Bits.Dpl").GetUlong();
                GdtEntry.Present = Gdt.ArrayElement(j).Field("HighWord.Bits.Pres").GetUlong();
                GdtEntry.Type = Gdt.ArrayElement(j).Field("HighWord.Bits.Type").GetUlong();

                if (GdtEntry.Type == CallGate32)
                {
                    CALL_GATE CallGate = { 0 };

                    ULONG64 Ptr = Gdt.ArrayElement(j).GetPointerTo().GetPtr();

                    if (g_Ext->m_Data->ReadVirtual(Ptr, &CallGate, sizeof(CallGate), NULL) == S_OK)
                    {
                        Entry = (CallGate.OffsetHigh << 16) | CallGate.OffsetLow;
                    }
                }

                GdtEntry.Base = Entry;

                GdtEntry.Index = j;
                GdtEntry.CoreIndex = i;

                Gdts.push_back(GdtEntry);
            }
        }
        else
        {
            for (UINT j = 0; j < 256; j += 1)
            {
                KGDTENTRY64 GdtEntry64 = { 0 };
                GDT_OBJECT GdtEntry = { 0 };

                if (g_Ext->m_Data->ReadVirtual(GdtBase + j * sizeof(KGDTENTRY64),
                    &GdtEntry64,
                    sizeof(GdtEntry64), NULL) != S_OK) goto CleanUp;

                ULONG64 Entry = GdtEntry64.BaseUpper;
                Entry <<= 32;
                Entry |= GdtEntry64.Bytes.BaseHigh << 24;
                Entry |= GdtEntry64.Bytes.BaseMiddle << 16;
                Entry |= GdtEntry64.BaseLow;


                if (GdtEntry.Type == CallGate32)
                {
                    CALL_GATE CallGate = { 0 };

                    ULONG64 Ptr = GdtBase + j * sizeof(KGDTENTRY64);

                    if (g_Ext->m_Data->ReadVirtual(Ptr, &CallGate, sizeof(CallGate), NULL) == S_OK)
                    {
                        Entry = (CallGate.OffsetHigh << 16) | CallGate.OffsetLow;
                    }
                }

                GdtEntry.Base = Entry;
                GdtEntry.Dpl = GdtEntry64.Bits.Dpl;
                GdtEntry.Present = GdtEntry64.Bits.Present;
                GdtEntry.Type = GdtEntry64.Bits.Type;
                GdtEntry.Limit = (GdtEntry64.Bits.LimitHigh << 16) | (GdtEntry64.LimitLow);

                GdtEntry.Index = j;
                GdtEntry.CoreIndex = i;

                Gdts.push_back(GdtEntry);
            }
        }
        i += 1;
    }

CleanUp:
    return Gdts;
}

LPSTR WorkQueueType[] = {
    "CriticalWorkQueue",
    "DelayedWorkQueue",
    "HyperCriticalWorkQueue",
    "NormalWorkQueue",
    "BackgroundWorkQueue",
    "RealTimeWorkQueue",
    "SuperCriticalWorkQueue",
    NULL
};

void
GetExQueue(
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
    // KeNodeBlock[i < KeNumberNodes] ENODE/KNODE
    // ExWorkerQueue = &ExGetNodeByNumber(i)->ExWorkerQueues[EXQUEUEINDEX_MAX];

    // ULONG ExCriticalWorkerThreads;
    // ULONG ExDelayedWorkerThreads;

    ExtRemoteTyped Nodes;

    if (g_Ext->m_Minor < 9200)
    {
        g_Ext->Execute("!exqueue");
        goto Exit;
    }

    USHORT KeNumberNodes = 0;
    ULONG64 KeNodeBlock;
    // ULONG MaxWorkQueue = 0;
    // GetFieldOffset("nt!_WORK_QUEUE_TYPE", "MaximumWorkQueue", &MaxWorkQueue);
    // g_Ext->Dml("MaxWorkQueue = %x\n", MaxWorkQueue);

    if (g_Ext->m_Data->ReadVirtual(GetExpression("nt!KeNumberNodes"), &KeNumberNodes, sizeof(KeNumberNodes), NULL) != S_OK) goto Exit;
    ReadPointer(GetExpression("nt!KeNodeBlock"), &KeNodeBlock);

    // g_Ext->Dml("KeNumberNodes = %x\nKeNodeBlock = %I64X\n", KeNumberNodes, KeNodeBlock);

    Nodes = ExtRemoteTyped("(nt!_ENODE *)@$extin", KeNodeBlock);

    for (ULONG i = 0; i < KeNumberNodes; i += 1)
    {
        ULONG64 ThreadPtr = Nodes.ArrayElement(i).Field("ExpWorkerThreadBalanceManagerPtr").GetPtr();
        g_Ext->Dml("ExpWorkerThreadBalanceManager = <link cmd=\"!thread 0x%I64X\">0x%I64X</link>\n\n",
            ThreadPtr, ThreadPtr);

        // g_Ext->Dml("Node = 0x%I64X\n", Nodes.GetPtr());
        // Nodes.ArrayElement(i).OutFullValue();

        for (ULONG j = 0; j < MaximumWorkQueue; j += 1)
        {
            ExtRemoteTyped WorkerQueue = Nodes.ArrayElement(i).Field("ExWorkerQueues").ArrayElement(j).Field("WorkerQueue");

            ULONG64 ThreadListHead = WorkerQueue.Field("ThreadListHead").GetPointerTo().GetPtr();

            ExtRemoteTypedList ThreadList(ThreadListHead, "nt!_ETHREAD", "Tcb.QueueListEntry");

            g_Ext->Dml("**** NUMA Node %d %-24s \n", i, WorkQueueType[j]);

            for (ThreadList.StartHead(); ThreadList.HasNode(); ThreadList.Next())
            {
                g_Ext->Dml("THREAD <link cmd=\"!thread 0x%I64X\">0x%I64X</link> Cid %04X.%04X Teb: 0x%I64X Win32Thread: 0x%I64X \n",
                           ThreadList.GetNodeOffset(), ThreadList.GetNodeOffset(),
                           (USHORT)ThreadList.GetTypedNode().Field("Cid.UniqueProcess").GetPtr(),
                           (USHORT)ThreadList.GetTypedNode().Field("Cid.UniqueThread").GetPtr(),
                           ThreadList.GetTypedNode().Field("Tcb.Teb").GetPtr(),
                           ThreadList.GetTypedNode().Field("Tcb.Win32Thread").GetPtr());
            }

            g_Ext->Dml("\n");
        }
    }

Exit:
    return;
}