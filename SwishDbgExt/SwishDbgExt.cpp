/*++
    MoonSols Incident Response & Digital Forensics Debugging Extension

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

    - SwishDbgExt.cpp
    - Codename: SOCOTRA

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

#ifdef _DEBUG
#define VERBOSE TRUE
#else
#define VERBOSE FALSE
#endif

BOOLEAN g_Verbose = VERBOSE;

class EXT_CLASS : public ExtExtension
{
public:
    EXT_COMMAND_METHOD(ms_dump);
    EXT_COMMAND_METHOD(ms_readkcb);
    EXT_COMMAND_METHOD(ms_readknode);
    EXT_COMMAND_METHOD(ms_readkvalue);

    EXT_COMMAND_METHOD(ms_netstat);

    EXT_COMMAND_METHOD(ms_object);

    EXT_COMMAND_METHOD(ms_timers);
    EXT_COMMAND_METHOD(ms_vacbs);

    EXT_COMMAND_METHOD(ms_hivelist);
    EXT_COMMAND_METHOD(ms_drivers);

    EXT_COMMAND_METHOD(ms_process);
    // EXT_COMMAND_METHOD(ms_handles);
    // EXT_COMMAND_METHOD(ms_dlls);
    // EXT_COMMAND_METHOD(ms_vads);
    // EXT_COMMAND_METHOD(ms_iat);
    // EXT_COMMAND_METHOD(ms_eat);


    EXT_COMMAND_METHOD(ms_credentials);

    EXT_COMMAND_METHOD(ms_consoles);

    EXT_COMMAND_METHOD(ms_ssdt);
    EXT_COMMAND_METHOD(ms_idt);
    EXT_COMMAND_METHOD(ms_gdt);
    EXT_COMMAND_METHOD(ms_mbr);

    EXT_COMMAND_METHOD(ms_callbacks);
    // EXT_COMMAND_METHOD(ms_drivers);
    // EXT_COMMAND_METHOD(ms_irp);
    // EXT_COMMAND_METHOD(ms_timers);

    EXT_COMMAND_METHOD(ms_services);

    // EXT_COMMAND_METHOD(ms_smlog);
    // EXT_COMMAND_METHOD(ms_smcache);
    EXT_COMMAND_METHOD(ms_sockets);

    EXT_COMMAND_METHOD(ms_malscore);

    EXT_COMMAND_METHOD(ms_exqueue);

    EXT_COMMAND_METHOD(ms_store);

    EXT_COMMAND_METHOD(ms_scanndishook);

    // EXT_COMMAND_METHOD(ms_strings);

    // EXT_COMMAND_METHOD(ms_virustotal);

    // EXT_COMMAND_METHOD(ms_analyze); // !ms_analyze -v

    EXT_COMMAND_METHOD(ms_checkcodecave);
    EXT_COMMAND_METHOD(ms_verbose);
    EXT_COMMAND_METHOD(ms_fixit);

};

EXT_DECLARE_GLOBALS();

EXT_COMMAND(ms_process,
    "Display list of processes",
    "{;e,o;;}"
    "{pid;ed,o;pid;Display process information for a given Process Id}"
    "{handletype;s,o;handletype;Display handles belonging to process\ntype (optional) - Object type to filter (e.g. Mutant or Key)}"
    "{handletable;ed,d=0;handletable;Handle table \ntype (optional)}"
    "{dlls;b,o;dlls;Display dlls belonging to process}"
    // "{dlls_exports;b,o;dlls exports;Display exports belonging to each dlls}"
    "{threads;b,o;threads;Display threads belonging to process}"
    "{vads;b,o;vads;Display VADs belonging to process}"
    "{vars;b,o;vars;Display environment variables}"
    "{exports;b,o;exports;Display exports belonging to process}"
    "{all;b,o;all;Display or scan all}"
    "{scan;b,o;scan;Display only malicious artifacts}")
{
    ULONG Flags = 0;
    ULONG64 Pid;
    BOOLEAN bScan = FALSE;

    Pid = GetArgU64("pid", FALSE);
    LPCSTR HandlesArg = GetArgStr("handletype", FALSE);
    ULONG64 HandleTable = GetArgU64("handletable", FALSE);
    if (HandlesArg || HandleTable) Flags |= PROCESS_HANDLES_FLAG;

    if (HasArg("vars")) Flags |= PROCESS_ENVVAR_FLAG;
    if (HasArg("threads")) Flags |= PROCESS_THREADS_FLAG;
    if (HasArg("vads")) Flags |= PROCESS_VADS_FLAG;
    if (HasArg("dlls")) Flags |= PROCESS_DLLS_FLAG;
    // if (HasArg("dlls_exports")) Flags |= PROCESS_DLLS_FLAG | PROCESS_DLL_EXPORTS_FLAG;
    if (HasArg("exports"))
    {
        Flags |= PROCESS_EXPORTS_FLAG;
        if (Flags & PROCESS_DLLS_FLAG) Flags |= PROCESS_DLL_EXPORTS_FLAG;
    }

    if (HasArg("all"))
    {
        Flags |= PROCESS_EXPORTS_FLAG | PROCESS_DLLS_FLAG | PROCESS_DLL_EXPORTS_FLAG | PROCESS_VADS_FLAG;
        Flags |= PROCESS_ENVVAR_FLAG;
        Flags |= PROCESS_THREADS_FLAG;
        Flags |= PROCESS_HANDLES_FLAG;
    }

    if (HasArg("scan"))
    {
        bScan = TRUE;
        Flags |= PROCESS_SCAN_MALICIOUS_FLAG;

        Flags &= ~PROCESS_ENVVAR_FLAG;
        Flags &= ~PROCESS_THREADS_FLAG;
        Flags &= ~PROCESS_HANDLES_FLAG;
    }

    ProcessArray CachedProcessList = GetProcesses(Pid, Flags);

    for each (MsProcessObject ProcObj in CachedProcessList)
    {
        Dml("\n<col fg=\"changed\">Process:</col>       <link cmd=\"!process %p 1\">%-20s</link> (PID=0x%4x) | "
            "[<link cmd=\"!ms_process /pid 0x%I64X /dlls\">+Dlls</link>] "
            "[<link cmd=\"!ms_process /pid 0x%I64X /dlls /exports\">+Exports</link>] "
            "[<link cmd=\"!ms_process /pid 0x%I64X /handles\">+Handles</link>] "
            "[<link cmd=\"!ms_process /pid 0x%I64X /threads\">+Threads</link>] "
            "[<link cmd=\"!ms_process /pid 0x%I64X /vads\">+VADs</link>] "
            "[<link cmd=\"!ms_process /pid 0x%I64X /all /scan\">+Scan</link>] "
            "[<link cmd=\".process /p /r 0x%016I64X \">+Select context</link>] "
            "\n",
            ProcObj.m_CcProcessObject.ProcessObjectPtr, ProcObj.m_CcProcessObject.ImageFileName,
            (ULONG)ProcObj.m_CcProcessObject.ProcessId,
            ProcObj.m_CcProcessObject.ProcessId,
            ProcObj.m_CcProcessObject.ProcessId,
            ProcObj.m_CcProcessObject.ProcessId,
            ProcObj.m_CcProcessObject.ProcessId,
            ProcObj.m_CcProcessObject.ProcessId,
            ProcObj.m_CcProcessObject.ProcessId,
            ProcObj.m_CcProcessObject.ProcessObjectPtr);
        if (wcslen(ProcObj.m_CcProcessObject.FullPath)) Dml("    <col fg=\"emphfg\">Path:          </col> %S\n", ProcObj.m_CcProcessObject.FullPath);
        if (strlen(ProcObj.m_PdbInfo.PdbName)) Dml("    <col fg=\"emphfg\">PDB:           </col> %s\n", ProcObj.m_PdbInfo.PdbName);
        if (wcslen(ProcObj.m_FileVersion.CompanyName)) Dml("    <col fg=\"emphfg\">Vendor:        </col> %S\n", ProcObj.m_FileVersion.CompanyName);
        if (wcslen(ProcObj.m_FileVersion.FileVersion)) Dml("    <col fg=\"emphfg\">Version:       </col> %S\n", ProcObj.m_FileVersion.FileVersion);
        if (wcslen(ProcObj.m_FileVersion.FileDescription)) Dml("    <col fg=\"emphfg\">Description:   </col> %S\n", ProcObj.m_FileVersion.FileDescription);
        if (ProcObj.m_CcProcessObject.CommandLine) Dml("    <col fg=\"emphfg\">Commandline:   </col> %S (%p)\n",
            ProcObj.m_CcProcessObject.CommandLine, ProcObj.m_CcProcessObject.CommandLine);

        Dml("    <col fg=\"emphfg\">Sections:</col>      ");
        for each (MsPEImageFile::CACHED_SECTION_INFO Section in ProcObj.m_CcSections)
        {
            Dml("%s, ", Section.Name);
        }
        Dml("\n");

        if (ProcObj.m_TypedObject.HasField("Flags2.ProtectedProcess"))
        {
            // Windows Vista+
        }
        else if (ProcObj.m_TypedObject.HasField("Protection"))
        {
            // Windows 8.1
        }

        if (Flags & PROCESS_ENVVAR_FLAG)
        {
            for each (MsProcessObject::ENV_VAR_OBJECT EnvVar in ProcObj.m_EnvVars)
            {
                Dml("    %S\n", EnvVar.Variable);
            }
        }

        if ((Flags & PROCESS_EXPORTS_FLAG) && (
            ((Flags & PROCESS_SCAN_MALICIOUS_FLAG) && ProcObj.m_NumberOfHookedAPIs) ||
            (!(Flags & PROCESS_SCAN_MALICIOUS_FLAG) && ProcObj.m_NumberOfExportedFunctions)))
        {
            Dml("    |------|------|--------------------|----------------------------------------------------|---------|\n"
                "    | <col fg=\"emphfg\">%-4s</col> | <col fg=\"emphfg\">%-4s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-50s</col> | <col fg=\"emphfg\">%-7s</col> | <col fg=\"emphfg\">%-6s</col> |\n"
                "    |------|------|--------------------|----------------------------------------------------|---------|\n",
                "Indx", "Ord", "Addr", "Name", "Patched", "Hooked");

            for each (MsPEImageFile::EXPORT_INFO ExportInfo in ProcObj.m_Exports)
            {
                ULONG64 Ptr = ProcObj.m_ImageBase + ExportInfo.Address;

                if (((Flags & PROCESS_SCAN_MALICIOUS_FLAG) && (ExportInfo.IsTablePatched || ExportInfo.IsHooked)) ||
                    !(Flags & PROCESS_SCAN_MALICIOUS_FLAG))
                {
                    Dml("    | %4d | %4d | <link cmd=\"u 0x%016I64X L1\">0x%016I64X</link> | <col fg=\"changed\">%-50s</col> | <col fg=\"changed\">%-7s</col> | <col fg=\"changed\">%-6s</col>\n",
                        ExportInfo.Index, ExportInfo.Ordinal,
                        Ptr, Ptr, ExportInfo.Name,
                        ExportInfo.IsTablePatched ? "Yes" : "No",
                        ExportInfo.IsHooked ? "Hooked" : "No");
                }
            }

            g_Ext->Dml("\n");
        }

        UINT i = 0;
        for each (MsDllObject DllObj in ProcObj.m_DllList)
        {
            Dml("    -> [%3d]: (%s) %S\n",
                i,
                DllObj.mm_CcDllObject.IsWow64 ? "<col fg=\"changed\">Wow64</col>" : "     ",
                DllObj.mm_CcDllObject.FullDllName);
            i += 1;

            if ((Flags & PROCESS_DLL_EXPORTS_FLAG) && (
                ((Flags & PROCESS_SCAN_MALICIOUS_FLAG) && DllObj.m_NumberOfHookedAPIs) ||
                (!(Flags & PROCESS_SCAN_MALICIOUS_FLAG) && DllObj.m_NumberOfExportedFunctions)))
            {
                Dml("    |------|------|--------------------|----------------------------------------------------|---------|\n"
                    "    | <col fg=\"emphfg\">%-4s</col> | <col fg=\"emphfg\">%-4s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-50s</col> | <col fg=\"emphfg\">%-7s</col> | <col fg=\"emphfg\">%-6s</col> |\n"
                    "    |------|------|--------------------|----------------------------------------------------|---------|\n",
                    "Indx", "Ord", "Addr", "Name", "Patched", "Hooked");

                for each (MsPEImageFile::EXPORT_INFO ExportInfo in DllObj.m_Exports)
                {
                    ULONG64 Ptr = DllObj.m_ImageBase + ExportInfo.Address;

                    if (((Flags & PROCESS_SCAN_MALICIOUS_FLAG) && (ExportInfo.IsTablePatched || ExportInfo.IsHooked)) ||
                        !(Flags & PROCESS_SCAN_MALICIOUS_FLAG))
                    {
                        Dml("    | %4d | %4d | <link cmd=\"u 0x%016I64X L1\">0x%016I64X</link> | <col fg=\"changed\">%-50s</col> | <col fg=\"changed\">%-7s</col> | <col fg=\"changed\">%-6s</col> \n",
                            ExportInfo.Index, ExportInfo.Ordinal,
                            Ptr, Ptr, ExportInfo.Name,
                            ExportInfo.IsTablePatched ? "Yes" : "No",
                            ExportInfo.IsHooked ? "Hooked" : "No");

                        if ((Flags & PROCESS_SCAN_MALICIOUS_FLAG) && ExportInfo.IsHooked)
                        {
                            ExecuteSilent(".process /p /r 0x%I64X", ProcObj.m_CcProcessObject.ProcessObjectPtr);
                            Execute("u 0x%I64X L3", Ptr);
                        }
                    }
                }
                Dml("\n");
            }
        }

        if (Flags & PROCESS_HANDLES_FLAG)
        {
            ProcObj.GetHandles(HandleTable);

            Dml("\n"
                "    |------|----------------------|--------------------|---------------------------------------------------------------------------|\n"
                "    | <col fg=\"emphfg\">%-4s</col> | <col fg=\"emphfg\">%-20s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-256s</col> |\n"
                "    |------|----------------------|--------------------|---------------------------------------------------------------------------|\n",
                "Hdle", "Object Type", "Addr", "Name");

            WCHAR ArgType[64] = { 0 };

            swprintf_s(ArgType, sizeof(ArgType), L"%S", HandlesArg);

            for each (HANDLE_OBJECT Handle in ProcObj.m_Handles)
            {
                if (wcslen(ArgType) && (_wcsicmp(ArgType, Handle.Type) != 0)) continue;

                if (_wcsicmp(Handle.Type, L"Key") == 0)
                {
                    Dml("    | %04x | %-20S | <link cmd=\"!ms_readkcb 0x%016I64X\">0x%016I64X</link> | %-256S | \n",
                        Handle.Handle, Handle.Type, Handle.ObjectKcb, Handle.ObjectPtr, Handle.Name);
                }
                else if (_wcsicmp(Handle.Type, L"Directory") == 0)
                {
                    Dml("    | %04x | %-20S | <link cmd=\"!ms_object 0x%016I64X\">0x%016I64X</link> | %-256S | \n",
                        Handle.Handle, Handle.Type, Handle.ObjectPtr, Handle.ObjectPtr, Handle.Name);
                }
                else
                {
                    Dml("    | %04x | %-20S | <link cmd=\"!object 0x%016I64X\">0x%016I64X</link> | %-256S | \n",
                        Handle.Handle, Handle.Type, Handle.ObjectPtr, Handle.ObjectPtr, Handle.Name);
                }
            }
            Dml("\n");
        }

        if (Flags & PROCESS_VADS_FLAG)
        {
            ProcObj.MmGetVads();

            Dml("\n"
                "    |----------------------|----------|--------------------|--------------------|---------------------------------------------------------------------------|\n"
                "    | <col fg=\"emphfg\">%-20s</col> | <col fg=\"emphfg\">%-8s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-256s</col> |\n"
                "    |----------------------|----------|--------------------|--------------------|---------------------------------------------------------------------------|\n",
                "Protection", "MalScore", "Start range", "End range", "FileObject");

            for each (VAD_OBJECT Vad in ProcObj.m_Vads)
            {
                ULONG MalScore = 0;
                HANDLE_OBJECT Handle = { 0 };
                BOOLEAN FoResult = ObReadObject(Vad.FileObject, &Handle);

                CHAR Protection[22] = { 0 };

                switch (Vad.Protection)
                {
                    case MM_READONLY:
                        strcpy_s(Protection, sizeof(Protection), "MM_READONLY");
                        break;
                    case MM_EXECUTE:
                        strcpy_s(Protection, sizeof(Protection), "MM_EXECUTE");
                        break;
                    case MM_EXECUTE_READ:
                        strcpy_s(Protection, sizeof(Protection), "MM_EXECUTE_READ");
                        break;
                    case MM_READWRITE:
                        strcpy_s(Protection, sizeof(Protection), "MM_READWRITE");
                        break;
                    case MM_WRITECOPY:
                        strcpy_s(Protection, sizeof(Protection), "MM_WRITECOPY");
                        break;
                    case MM_EXECUTE_READWRITE:
                        strcpy_s(Protection, sizeof(Protection), "MM_EXECUTE_READWRITE");
                        break;
                    case MM_EXECUTE_WRITECOPY:
                        strcpy_s(Protection, sizeof(Protection), "MM_EXECUTE_WRITECOPY");
                        break;
                }

                ULONG VadSize = (ULONG)((Vad.EndingVpn - Vad.StartingVpn) * PAGE_SIZE);
                ULONG64 BaseAddress = Vad.StartingVpn * PAGE_SIZE;

                if (bScan)
                {
                    MalScore = GetMalScoreEx(FALSE, &ProcObj, BaseAddress, VadSize);
                }

                Dml("    | %-20s | <link cmd=\"!ms_malscore 0x%016I64X 0x%X\">%8d</link> | 0x%016I64X | 0x%016I64X | (0x%016I64X) %S |\n",
                    Protection,
                    BaseAddress, VadSize, MalScore,
                    Vad.StartingVpn * PAGE_SIZE,
                    Vad.EndingVpn * PAGE_SIZE,
                    Vad.FileObject,
                    FoResult ? Handle.Name : L""
                    );
            }

            ReleaseObjectTypeTable();
        }

        if (Flags & PROCESS_THREADS_FLAG)
        {
            ProcObj.GetThreads();

            Dml("    |--------|--------|--------------------|----------------------------------------------------|---------------------|---------------------|\n"
                "    | <col fg=\"emphfg\">%-6s</col> | <col fg=\"emphfg\">%-6s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-50s</col> | Create time         | Exit time           |\n"
                "    |--------|--------|--------------------|----------------------------------------------------|---------------------|---------------------|\n",
                "Proc", "Thrd", "Addr", "Name");

            for each (THREAD_OBJECT Thread in ProcObj.m_Threads)
            {
                UCHAR Name[512] = { 0 };
                UCHAR TimerType[32] = { 0 };

                SYSTEMTIME CreateTime, ExitTime;

                if (Thread.StartAddress)
                {
                    FileTimeToSystemTime((FILETIME *)&Thread.CreateTime, &CreateTime);
                    FileTimeToSystemTime((FILETIME *)&Thread.ExitTime, &ExitTime);

                    Dml("    | 0x%04x | 0x%04x | <link cmd=\"u 0x%016I64X L3\">0x%016I64X</link> | %-50s | %02d/%02d/%4d %02d:%02d:%02d | %02d/%02d/%4d %02d:%02d:%02d |\n",
                        (ULONG)Thread.ProcessId, (ULONG)Thread.ThreadId, Thread.StartAddress, Thread.StartAddress,
                        GetNameByOffset(Thread.StartAddress, (PSTR)Name, _countof(Name)),
                        CreateTime.wDay, CreateTime.wMonth, CreateTime.wYear, CreateTime.wHour, CreateTime.wMinute, CreateTime.wSecond,
                        ExitTime.wDay, ExitTime.wMonth, ExitTime.wYear, ExitTime.wHour, ExitTime.wMinute, ExitTime.wSecond);
                }
            }
        }
    }
}

EXT_COMMAND(ms_object,
           "Display list of object",
           "{;ed,d=0;object;Object directory}")
{
    ULONG64 Object = GetUnnamedArgU64(0);
    HANDLE_OBJECT Handle = {0};

    vector<HANDLE_OBJECT> Handles = ObOpenObjectDirectory(Object);

    if (Object)
    {
        ObReadObject(Object, &Handle);
        Dml("\n    Object: %S (%S)", Handle.Name, Handle.Type);

        if (_wcsicmp(Handle.Type, L"Directory") != 0) return;
    }
    else
    {
        Dml("\n    Object: \\ (Directory)");
    }

    Dml("\n"
        "    |------|----------------------|--------------------|---------------------------------------------------------------------------|\n"
        "    | <col fg=\"emphfg\">%-4s</col> | <col fg=\"emphfg\">%-20s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-256s</col> |\n"
        "    |------|----------------------|--------------------|---------------------------------------------------------------------------|\n",
        "Hdle", "Object Type", "Addr", "Name");

    for each (Handle in Handles)
    {
        if (_wcsicmp(Handle.Type, L"Key") == 0)
        {
            Dml("    | %04x | %-20S | <link cmd=\"!ms_readkcb 0x%016I64X\">0x%016I64X</link> | %-256S | \n",
                Handle.Handle, Handle.Type, Handle.ObjectKcb, Handle.ObjectPtr, Handle.Name);
        }
        else if (_wcsicmp(Handle.Type, L"Directory") == 0)
        {
            Dml("    | %04x | %-20S | <link cmd=\"!ms_object 0x%016I64X\">0x%016I64X</link> | %-256S | \n",
                Handle.Handle, Handle.Type, Handle.ObjectPtr, Handle.ObjectPtr, Handle.Name);
        }
        else if (_wcsicmp(Handle.Type, L"File") == 0)
        {
            Dml("    | %04x | %-20S | <link cmd=\"!fileobj 0x%016I64X\">0x%016I64X</link> | %-256S | \n",
                Handle.Handle, Handle.Type, Handle.ObjectPtr, Handle.ObjectPtr, Handle.Name);
        }
        else
        {
            Dml("    | %04x | %-20S | <link cmd=\"!object 0x%016I64X\">0x%016I64X</link> | %-256S | \n",
                Handle.Handle, Handle.Type, Handle.ObjectPtr, Handle.ObjectPtr, Handle.Name);
        }
    }
    Dml("    |------|----------------------|--------------------|---------------------------------------------------------------------------|\n");
    Dml("\n");
}

EXT_COMMAND(ms_drivers,
    "Display list of drivers",
    "{;e,o;;}"
    "{object;ed,o;drvobj;Display driver information for a given driven object}"
    "{scan;b,o;scan;Display only malicious artifacts}")
{
    ULONG64 DrvObj = GetArgU64("object", FALSE);
    BOOLEAN Scan = HasArg("scan");

    vector<MsDriverObject> Drivers = GetDrivers();

    for each (MsDriverObject Driver in Drivers)
    {
        if (DrvObj && (Driver.m_ObjectPtr != DrvObj)) continue;

        OutDriver(&Driver, (DrvObj || Scan) ? TRUE : FALSE);
    }
}

EXT_COMMAND(ms_services,
    "Display list of services",
    "{;e,o;;}")
{
    vector<SERVICE_ENTRY> Services = GetServices();
    UINT i = 0;

    LPSTR ServiceStatus[] = {
        "SERVICE_NONE",
        "SERVICE_STOPPED",
        "SERVICE_START_PENDING",
        "SERVICE_STOP_PENDING",
        "SERVICE_RUNNING",
        "SERVICE_CONTINUE_PENDING",
        "SERVICE_PAUSE_PENDING",
        "SERVICE_PAUSED",
        NULL };

    Dml("   Additional information (Registry): <link cmd=\"!reg findkcb %s\">%s</link> (Use KCB addr with \"!ms_readkcb\")\n",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES");

    for each (SERVICE_ENTRY ServiceEntry in Services)
    {
        if (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_KERNEL_DRIVER)
        {
            Dml("\n[%3d] | 0x%02X |           | <col fg=\"changed\">%-32S</col> | %-50S | %-16s | %-100S | ",
                i, ServiceEntry.ServiceStatus.dwServiceType, 
                ServiceEntry.Name, ServiceEntry.Desc, ServiceStatus[ServiceEntry.ServiceStatus.dwCurrentState], ServiceEntry.CommandLine);
        }
        else if ((ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_OWN_PROCESS) ||
                 (ServiceEntry.ServiceStatus.dwServiceType == SERVICE_WIN32_SHARE_PROCESS))
        {
            Dml("\n[%3d] | 0x%02X | <link cmd=\"!process %x 1\">Pid=0x%x</link> | <col fg=\"changed\">%-32S</col> | %-50S | %-16s | %-128S | ",
                i, ServiceEntry.ServiceStatus.dwServiceType,
                ServiceEntry.ProcessId, ServiceEntry.ProcessId, ServiceEntry.Name,
                ServiceEntry.Desc, ServiceStatus[ServiceEntry.ServiceStatus.dwCurrentState], ServiceEntry.CommandLine);
        }

        i += 1;
    }
    Dml("\n");
}

EXT_COMMAND(ms_callbacks,
            "Display callback functions",
            "{;e,o;;}")
{
    ULONG64 Offset;
    CHAR Buffer[512] = {0};

    ULONG BuildNumber;

    if (g_Ext->m_Symbols->GetOffsetByName("nt!NtBuildNumber", &Offset) != S_OK) goto Exit;
    if (g_Ext->m_Data->ReadVirtual(Offset, (PUCHAR)&BuildNumber, sizeof(BuildNumber), NULL) != S_OK) goto Exit;

    if (g_Ext->m_Symbols->GetOffsetByName("nt!IopFsNotifyChangeQueueHead", &Offset) == S_OK)
    {
        // typedef struct _FS_CHANGE_NOTIFY_ENTRY
        // {
        //      LIST_ENTRY FsChangeNotifyList;
        //      PDRIVER_OBJECT DriverObject;
        //      PDRIVER_FS_NOTIFICATION FSDNotificationProc;
        // } FS_CHANGE_NOTIFY_ENTRY, *PFS_CHANGE_NOTIFY_ENTRY;

        ExtRemoteTypedList IopFsNotifyChangeQueueHead(Offset, "nt!_LIST_ENTRY", "Flink");

        Dml("\n<col fg=\"changed\">[*] IopFsNotifyChangeQueueHead:</col>\n");

        for (IopFsNotifyChangeQueueHead.StartHead();
             IopFsNotifyChangeQueueHead.HasNode();
             IopFsNotifyChangeQueueHead.Next())
        {
            ULONG64 Node = IopFsNotifyChangeQueueHead.GetNodeOffset();
            ULONG TypeSize;
            ULONG64 DrvObj, NotificationProc;

            TypeSize = GetTypeSize("nt!_LIST_ENTRY");

            ReadPointer(Node + TypeSize, &DrvObj);
            ReadPointer(Node + TypeSize + m_PtrSize, &NotificationProc);

            Dml("     Object: 0x%016I64X "
                "Driver Object: <link cmd=\"dt nt!_DRIVER_OBJECT 0x%016I64X\">0x%016I64X</link> "
                "Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                Node, DrvObj, DrvObj, NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if ((g_Ext->m_Symbols->GetOffsetByName("nt!PnpProfileNotifyList", &Offset) == S_OK) ||
        (g_Ext->m_Symbols->GetOffsetByName("nt!IopProfileNotifyList", &Offset) == S_OK))
    {
        //typedef struct _NOTIFY_ENTRY_HEADER {
        //    LIST_ENTRY ListEntry;
        //    IO_NOTIFICATION_EVENT_CATEGORY EventCategory;
        //    ULONG SessionId;
        //    HANDLE SessionHandle;
        //    PDRIVER_NOTIFICATION_CALLBACK_ROUTINE CallbackRoutine;
        //    PVOID Context;
        //    PDRIVER_OBJECT DriverObject;
        // (...)
        ExtRemoteTypedList PnpProfileNotifyList(Offset, "nt!_LIST_ENTRY", "Flink");

        Dml("\n<col fg=\"changed\">[*] PnpProfileNotifyList/:</col>\n");

        for (PnpProfileNotifyList.StartHead();
            PnpProfileNotifyList.HasNode();
            PnpProfileNotifyList.Next())
        {
            ULONG64 Node = PnpProfileNotifyList.GetNodeOffset();
            ULONG FieldOffset;
            ULONG64 SessionHandle;
            ULONG64 NotificationProc;
            ULONG64 DrvObj;

            FieldOffset = GetTypeSize("nt!_LIST_ENTRY");
            FieldOffset += sizeof(ULONG);
            FieldOffset += sizeof(ULONG);

            ReadPointer(Node + FieldOffset, &SessionHandle);
            FieldOffset += m_PtrSize;

            ReadPointer(Node + FieldOffset, &NotificationProc);
            FieldOffset += m_PtrSize *2;
            ReadPointer(Node + FieldOffset, &DrvObj);

            Dml("     Object: 0x%016I64X "
                "Driver Object: <link cmd=\"dt nt!_DRIVER_OBJECT 0x%016I64X\">0x%016I64X</link> "
                "Session: <link cmd=\"!session 0x%I64X\">0x%I64X</link> "
                "Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                Node, DrvObj, DrvObj, SessionHandle, SessionHandle, NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    // TODO: IopNotifyShutdownQueueHead
    // TODO: IopCdRomFileSystemQueueHead
    // TODO: IopDiskFileSystemQueueHead
    // TODO: IopTapeFileSystemQueueHead
    // TODO: IopNetworkFileSystemQueueHead

    if (g_Ext->m_Symbols->GetOffsetByName("nt!PspCreateProcessNotifyRoutine", &Offset) == S_OK)
    {
        // typedef struct _EX_CALLBACK_ROUTINE_BLOCK
        // {
        //      EX_RUNDOWN_REF RundownProtect;
        //      PEX_CALLBACK_FUNCTION Function;
        //      PVOID Context;
        // } EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

        ULONG PspCreateProcessNotifyRoutineCount = 0;
        ULONG PspCreateProcessNotifyRoutineExCount = 0;
        ULONG64 ExRefMask = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? ~0xF : ~0x7;
        ULONG64 Offset2;

        if (g_Ext->m_Symbols->GetOffsetByName("nt!PspCreateProcessNotifyRoutineCount", &Offset2) == S_OK)
        {
            g_Ext->m_Data->ReadVirtual(Offset2, (PUCHAR)&PspCreateProcessNotifyRoutineCount, sizeof(PspCreateProcessNotifyRoutineCount), NULL);
        }

        if (g_Ext->m_Symbols->GetOffsetByName("nt!PspCreateProcessNotifyRoutineExCount", &Offset2) == S_OK)
        {
            g_Ext->m_Data->ReadVirtual(Offset2, (PUCHAR)&PspCreateProcessNotifyRoutineExCount, sizeof(PspCreateProcessNotifyRoutineExCount), NULL);
        }

        Dml("\n<col fg=\"changed\">[*] PspCreateProcessNotifyRoutine:</col>\n");

        for (ULONG Index = 0;
            Index < (PspCreateProcessNotifyRoutineCount + PspCreateProcessNotifyRoutineExCount);
            Index += 1)
        {
            ULONG64 NotificationProc;
            ReadPointer(Offset + (Index * m_PtrSize), &NotificationProc);
            NotificationProc &= ExRefMask;

            ULONG TypeSize = GetTypeSize("nt!EX_RUNDOWN_REF");
            if (!TypeSize) TypeSize = m_PtrSize;

            ReadPointer(NotificationProc + TypeSize, &NotificationProc);

                Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                    NotificationProc, NotificationProc,
                    GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!PspLoadImageNotifyRoutine", &Offset) == S_OK)
    {
        // typedef struct _EX_CALLBACK_ROUTINE_BLOCK
        // {
        //      EX_RUNDOWN_REF RundownProtect;
        //      PEX_CALLBACK_FUNCTION Function;
        //      PVOID Context;
        // } EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;
        ULONG64 ExRefMask = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? ~0xF : ~0x7;
        ULONG64 Offset2;
        ULONG Count = 0;

        if (g_Ext->m_Symbols->GetOffsetByName("nt!PspLoadImageNotifyRoutineCount", &Offset2) == S_OK)
        {
            g_Ext->m_Data->ReadVirtual(Offset2, (PUCHAR)&Count, sizeof(Count), NULL);
        }

        Dml("\n<col fg=\"changed\">[*] PspLoadImageNotifyRoutine:</col>\n");

        for (ULONG Index = 0;
            Index < Count;
            Index += 1)
        {
            ULONG64 NotificationProc;
            ReadPointer(Offset + (Index * m_PtrSize), &NotificationProc);
            NotificationProc &= ExRefMask;

            ULONG ProcOffset = GetTypeSize("nt!EX_RUNDOWN_REF");
            if (!ProcOffset) ProcOffset = m_PtrSize;

            ReadPointer(NotificationProc + ProcOffset, &NotificationProc);

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
         }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!PspCreateThreadNotifyRoutine", &Offset) == S_OK)
    {
        // typedef struct _EX_CALLBACK_ROUTINE_BLOCK
        // {
        //      EX_RUNDOWN_REF RundownProtect;
        //      PEX_CALLBACK_FUNCTION Function;
        //      PVOID Context;
        // } EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;
        ULONG64 ExRefMask = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? ~0xF : ~0x7;
        ULONG64 pPspCreateThreadNotifyRoutineCount;
        ULONG Count = 0;

        pPspCreateThreadNotifyRoutineCount = GetExpression("nt!PspCreateThreadNotifyRoutineCount");

        if (pPspCreateThreadNotifyRoutineCount)
        {
            g_Ext->m_Data->ReadVirtual(pPspCreateThreadNotifyRoutineCount, (PUCHAR)&Count, sizeof(Count), NULL);
        }

        Dml("\n<col fg=\"changed\">[*] PspCreateThreadNotifyRoutine:</col>\n");
        for (ULONG Index = 0;
            Index < Count;
            Index += 1)
        {
            ULONG64 NotificationProc;

            ReadPointer(Offset + (Index * m_PtrSize), &NotificationProc);
            NotificationProc &= ExRefMask;

            ULONG ProcOffset = GetTypeSize("nt!EX_RUNDOWN_REF");
            if (!ProcOffset) ProcOffset = m_PtrSize;

            ReadPointer(NotificationProc + ProcOffset, &NotificationProc);

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!CmpCallBackVector", &Offset) == S_OK)
    {
        // typedef struct _EX_CALLBACK_ROUTINE_BLOCK
        // {
        //      EX_RUNDOWN_REF RundownProtect;
        //      PEX_CALLBACK_FUNCTION Function;
        //      PVOID Context;
        // } EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;
        ULONG64 ExRefMask = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? ~0xF : ~0x7;
        ULONG64 pCmpCallBackCount;
        ULONG Count = 0;

        pCmpCallBackCount = GetExpression("nt!CmpCallBackCount");

        if (pCmpCallBackCount)
        {
            g_Ext->m_Data->ReadVirtual(pCmpCallBackCount, (PUCHAR)&Count, sizeof(Count), NULL);

            Dml("\n<col fg=\"changed\">[*] CmpCallBackVector:</col>\n");
        }

        for (ULONG Index = 0;
            Index < Count;
            Index += 1)
        {
            ULONG64 NotificationProc;
            ReadPointer(Offset + (Index * m_PtrSize), &NotificationProc);
            NotificationProc &= ExRefMask;

            ULONG ProcOffset = GetTypeSize("nt!EX_RUNDOWN_REF");
            if (!ProcOffset) ProcOffset = m_PtrSize;

            ReadPointer(NotificationProc + ProcOffset, &NotificationProc);

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!CallbackListHead", &Offset) == S_OK)
    {
        //typedef struct _CM_CALLBACK_CONTEXT_BLOCK {
        //    LIST_ENTRY                  CallbackListEntry;      // List of all the callbacks registered in the system
        //    LONG                        PreCallListCount;       // Number of already active pre callbacks
        //    LARGE_INTEGER               Cookie;                 // to identify a specific callback for deregistration purposes
        //    PVOID                       CallerContext;
        //    PEX_CALLBACK_FUNCTION       Function;               // the actual callback routine
        //    UNICODE_STRING              Altitude;
        //    LIST_ENTRY                  ObjectContextListHead;  // Links together object contexts for this callback
        //} CM_CALLBACK_CONTEXT_BLOCK, *PCM_CALLBACK_CONTEXT_BLOCK;
        ExtRemoteTypedList CallbackListHead(Offset, "nt!_LIST_ENTRY", "Flink");

        Dml("\n<col fg=\"changed\">[*] CallbackListHead:</col>\n");

        for (CallbackListHead.StartHead();
            CallbackListHead.HasNode();
            CallbackListHead.Next())
        {
            ULONG64 Node = CallbackListHead.GetNodeOffset();
            ULONG64 NotificationProc;

            ULONG ProcOffset = GetTypeSize("nt!_LIST_ENTRY");
            ProcOffset += m_PtrSize;// sizeof(ULONG); // ULONG but 8-bytes aligned.
            ProcOffset += sizeof(LARGE_INTEGER);
            ProcOffset += m_PtrSize;

            if (!ReadPointer(Node + ProcOffset, &NotificationProc)) continue;

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!KeBugCheckCallbackListHead", &Offset) == S_OK)
    {
        // typedef struct _KBUGCHECK_REASON_CALLBACK_RECORD {
        //   LIST_ENTRY Entry;
        //   PKBUGCHECK_REASON_CALLBACK_ROUTINE CallbackRoutine;
        //   PUCHAR Component;
        //   ULONG_PTR Checksum;
        //   KBUGCHECK_CALLBACK_REASON Reason;
        //   UCHAR State;
        // } KBUGCHECK_REASON_CALLBACK_RECORD, *PKBUGCHECK_REASON_CALLBACK_RECORD;

        ExtRemoteTypedList CallbackListHead(Offset, "nt!_LIST_ENTRY", "Flink");

        Dml("\n<col fg=\"changed\">[*] KeBugCheckCallbackListHead:</col>\n");

        for (CallbackListHead.StartHead();
            CallbackListHead.HasNode();
            CallbackListHead.Next())
        {
            ULONG64 Node = CallbackListHead.GetNodeOffset();
            ULONG64 NotificationProc;

            ULONG ProcOffset = GetTypeSize("nt!_LIST_ENTRY");

            ReadPointer(Node + ProcOffset, &NotificationProc);

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!KeBugCheckAddPagesCallbackListHead", &Offset) == S_OK)
    {
        // typedef struct _KBUGCHECK_REASON_CALLBACK_RECORD {
        //   LIST_ENTRY Entry;
        //   PKBUGCHECK_REASON_CALLBACK_ROUTINE CallbackRoutine;
        //   PUCHAR Component;
        //   ULONG_PTR Checksum;
        //   KBUGCHECK_CALLBACK_REASON Reason;
        //   UCHAR State;
        // } KBUGCHECK_REASON_CALLBACK_RECORD, *PKBUGCHECK_REASON_CALLBACK_RECORD;

        ExtRemoteTypedList CallbackListHead(Offset, "nt!_LIST_ENTRY", "Flink");

        Dml("\n<col fg=\"changed\">[*] KeBugCheckAddPagesCallbackListHead:</col>\n");

        for (CallbackListHead.StartHead();
            CallbackListHead.HasNode();
            CallbackListHead.Next())
        {
            ULONG64 Node = CallbackListHead.GetNodeOffset();
            ULONG64 NotificationProc;

            ULONG ProcOffset = GetTypeSize("nt!_LIST_ENTRY");

            ReadPointer(Node + ProcOffset, &NotificationProc);

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!KiNmiCallbackListHead", &Offset) == S_OK)
    {
        // typedef struct _KNMI_HANDLER_CALLBACK {
        //     struct _KNMI_HANDLER_CALLBACK * Next;
        //     PNMI_CALLBACK Callback;
        //     PVOID Context;
        //     PVOID Handle;
        // } KNMI_HANDLER_CALLBACK, *PKNMI_HANDLER_CALLBACK;

        ExtRemoteTypedList CallbackListHead(Offset, "nt!_SINGLE_LIST_ENTRY", "Next");

        Dml("\n<col fg=\"changed\">[*] KiNmiCallbackListHead:</col>\n");

        for (CallbackListHead.StartHead();
            CallbackListHead.HasNode();
            CallbackListHead.Next())
        {
            ULONG64 Node = CallbackListHead.GetNodeOffset();
            ULONG64 NotificationProc;

            ULONG ProcOffset = GetTypeSize("nt!_SINGLE_LIST_ENTRY");

            ReadPointer(Node + ProcOffset, &NotificationProc);

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!AlpcpLogCallbackListHead", &Offset) == S_OK)
    {
        // typedef struct _ALPC_PRIVATE_LOG_CALLBACK {
        //     LIST_ENTRY Entry;
        //     PVOID LogRoutine;
        // } ALPC_PRIVATE_LOG_CALLBACK, *PALPC_PRIVATE_LOG_CALLBACK;

        ExtRemoteTypedList CallbackListHead(Offset, "nt!_LIST_ENTRY", "Flink");

        Dml("\n<col fg=\"changed\">[*] AlpcpLogCallbackListHead:</col>\n");

        for (CallbackListHead.StartHead();
            CallbackListHead.HasNode();
            CallbackListHead.Next())
        {
            ULONG64 Node = CallbackListHead.GetNodeOffset();
            ULONG64 NotificationProc;

            ULONG ProcOffset = GetTypeSize("nt!_LIST_ENTRY");

            ReadPointer(Node + ProcOffset, &NotificationProc);

            Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                NotificationProc, NotificationProc,
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    if (g_Ext->m_Symbols->GetOffsetByName("nt!EmpCallbackListHead", &Offset) == S_OK)
    {
        // struct _EMP_CALLBACK {
        // GUID CallbackId;
        // PVOID CallbackFunc;
        // LONG CallbackFuncReference;
        // PVOID Context;
        // SINGLE_LIST_ENTRY List;
        // ...
        // };

        ExtRemoteTypedList CallbackListHead(Offset, "nt!_SINGLE_LIST_ENTRY", "Next");

        Dml("\n<col fg=\"changed\">[*] EmpCallbackListHead:</col>\n");

        for (CallbackListHead.StartHead();
            CallbackListHead.HasNode();
            CallbackListHead.Next())
        {
            GUID Guid;
            ULONG64 NotificationProc;
            ULONG64 Node = CallbackListHead.GetNodeOffset();

            ULONG ProcOffset = m_PtrSize * 2 + m_PtrSize; // ULONG but 8 bytes aligned. sizeof(ULONG);

            ReadPointer(Node - ProcOffset, &NotificationProc);

            g_Ext->m_Data->ReadVirtual(SIGN_EXTEND(Node - ProcOffset - sizeof(GUID)), (PUCHAR)&Guid, sizeof(GUID), NULL);

            Dml("     GUID: {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX} "
                "Procedure: <link cmd = \"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                Guid.Data1, Guid.Data2, Guid.Data3,
                Guid.Data4[0], Guid.Data4[1], Guid.Data4[2], Guid.Data4[3],
                Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7],
                NotificationProc, NotificationProc, 
                GetNameByOffset(NotificationProc, (PSTR)Buffer, _countof(Buffer)));
        }
    }

    // TODO: NmrRegisterProvider() http://wenku.baidu.com/view/c79f672acfc789eb172dc8a5.html

    if (g_Ext->m_Symbols->GetOffsetByName("tcpip!IOCtlDispatchTable", &Offset) == S_OK)
    {
        //
        // typedef struct _IOCTL_DISPATCH_ENTRY {
        // PDEVICE_OBJECT DeviceObject;
        // PVOID DeviceControlDispatchFunction;
        // } IOCTL_DISPATCH_ENTRY;
        // 

        ULONG64 DeviceObjectDispatchEntry[2 * NetIoDispatchMax];
        LPSTR TcpipDispatchId[] = {
            "IPSEC",
            "KFD",
            "ALE",
            "EQOS",
            "IDP",
            NULL
        };

        if (ReadPointersVirtual(NetIoDispatchMax * 2, Offset, (PULONG64)&DeviceObjectDispatchEntry) != S_OK) goto Exit;

        Dml("\n<col fg=\"changed\">[*] Tcpip driver IOCTL dispatch table:</col>\n");

        for (UINT i = 0; i < NetIoDispatchMax; i += 1)
        {
            Dml("   | %5s |  DevObj: <link cmd = \"!devobj 0x%016I64X f\">0x%016I64X</link> | IoctlDispatch: <link cmd = \"u 0x%016I64X L5\">0x%016I64X</link> | %s | <col fg=\"changed\">%s</col> \n",
                TcpipDispatchId[i],
                DeviceObjectDispatchEntry[i * 2],
                DeviceObjectDispatchEntry[i * 2],
                DeviceObjectDispatchEntry[(i * 2) + 1],
                DeviceObjectDispatchEntry[(i * 2) + 1],
                GetNameByOffset(DeviceObjectDispatchEntry[(i * 2) + 1], (PSTR)Buffer, _countof(Buffer)),
                IsPointerHooked(DeviceObjectDispatchEntry[(i * 2) + 1]) ? "Hooked" : "");
        }
    }

    // TODO: LKMD_CALLBACK DbgkpLkmdDataCollectionCallbacks[8]

    /*
     DBG_LKMD_CALLBACK {
        EX_CALLBACK Callback;
        EX_FAST_REF RoutineBlock;
        PVOID Object;
        // ...
     }

    16.kd : x86> ? ? sizeof(nt!_LKMD_CALLBACK)
        unsigned int 0x10

    16.kd:x86> dt nt!_EX_CALLBACK
        + 0x000 RoutineBlock     : _EX_FAST_REF
        16.kd : x86> dt nt!_EX_FAST_REF
        16.kd:x86> dt nt!_EX_FAST_REF
        + 0x000 Object           : Ptr64 Void
        + 0x000 RefCnt : Pos 0, 4 Bits
        + 0x000 Value : Uint8B
        16.kd : x86> dt nt!_EX_CALLBACK_ROUTINE_BLOCK
        16.kd:x86> dt nt!_EX_CALLBACK_ROUTINE_BLOCK
        + 0x000 RundownProtect   : _EX_RUNDOWN_REF
        + 0x008 Function : Ptr64     long
        + 0x010 Context : Ptr64 Void
        */

    if (g_Ext->m_Symbols->GetOffsetByName("nt!DbgkpLkmdDataCollectionCallbacks", &Offset) == S_OK)
    {
        #define MAX_DBG_LKMD_CALLBACKS 8 
        ULONG64 DbgLkmdCallbacks[2 * MAX_DBG_LKMD_CALLBACKS];

        Dml("\n<col fg=\"changed\">[*] DbgkpLkmdDataCollectionCallbacks:</col>\n");

        if (ReadPointersVirtual(MAX_DBG_LKMD_CALLBACKS * 2, Offset, (PULONG64)&DbgLkmdCallbacks) != S_OK) goto Exit;

        for (UINT i = 0; i < MAX_DBG_LKMD_CALLBACKS; i += 1)
        {
            ULONG64 CallbackRoutine = GetFastRefPointer(DbgLkmdCallbacks[i * 2]);
            if (CallbackRoutine)
            {
                Dml("     Procedure: <link cmd=\"u 0x%016I64X L5\">0x%016I64X</link> (%s) \n",
                    CallbackRoutine, CallbackRoutine,
                    GetNameByOffset(CallbackRoutine, (PSTR)Buffer, _countof(Buffer)));
            }
        }
    }

Exit:
    return;
}

EXT_COMMAND(ms_ssdt,
    "Display service descriptor table (SDT) functions",
    "{;e,o;;}")
{
    vector<SSDT_ENTRY> Table = GetServiceDescriptorTable();

    // Dml("\n<col fg=\"changed\">[*] Service Descriptor Table:</col>\n");

    Dml("    |-------|--------------------|--------------------------------------------------------|---------|--------|\n"
        "    | <col fg=\"emphfg\">%-5s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-54s</col> | <col fg=\"emphfg\">%-7s</col> | <col fg=\"emphfg\">%-6s</col> |\n"
        "    |-------|--------------------|--------------------------------------------------------|---------|--------|\n",
        "Index", "Address", "Name", "Patched", "Hooked");

    for each (SSDT_ENTRY Entry in Table)
    {
        UCHAR Name[512] = { 0 };

        Dml("    | %5d |  <link cmd=\"u 0x%016I64X L1\">0x%016I64X</link> | %-54s | <col fg=\"changed\">%-7s</col> | <col fg=\"changed\">%-6s</col> |\n",
            Entry.Index,
            Entry.Address,
            Entry.Address,
            GetNameByOffset(Entry.Address, (PSTR)Name, _countof(Name)),
            Entry.PatchedEntry ? "Yes" : "",
            IsPointerHooked(Entry.Address) ? "Yes" : "");
    }
}

EXT_COMMAND(ms_dump,
            "Dump memory space on disk",
            "{;s;outputfile;Output file}{;ed;base;Base address}{;ed;size;Memory space size}")
{
    PCSTR Output = GetUnnamedArgStr(0);
    ULONG64 BaseAddress = GetUnnamedArgU64(1);
    ULONG Size = (ULONG)GetUnnamedArgU64(2);

    ULONG WrittenBytes = 0;

    Dml("   [ <col fg=\"changed\">File:</col> <col fg=\"emphfg\">%s</col>\n"
        "   [ <col fg=\"changed\">Base:</col> <col fg=\"emphfg\">0x%016I64X</col>\n"
        "   [ <col fg=\"changed\">Size:</col> <col fg=\"emphfg\">0x%X</col>\n",
        Output, BaseAddress, Size);

    PVOID Buffer = malloc(Size);

    if (ExtRemoteTypedEx::ReadVirtual(BaseAddress, Buffer, Size, NULL) != S_OK)
    {
        Err("Error: Failed to read the memory buffer.\n");
        goto CleanUp;
    }

    Dml("   -> Dumping memory address space in file... ",
        Output, BaseAddress, Size);
    HANDLE hOutput = CreateFile(Output,
                                GENERIC_WRITE,
                                0,
                                NULL,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
    if (hOutput == INVALID_HANDLE_VALUE)
    {
        g_Ext->Dml("<col fg=\"emphfg\">Failed</col>\n");
        goto CleanUp;
    }

    BOOL Ret = WriteFile(hOutput, Buffer, Size, &WrittenBytes, NULL);

    if ((Ret == FALSE) && (GetLastError() == ERROR_IO_PENDING))
    {
        DWORD Status;

        do
        {
            Status = WaitForSingleObjectEx(hOutput, INFINITE, TRUE);
        } while (Status == WAIT_IO_COMPLETION);
    }

    CloseHandle(hOutput);

    g_Ext->Dml("<col fg=\"emphfg\">Success</col>\n");

CleanUp:
    if (Buffer) free(Buffer);
}

EXT_COMMAND(ms_readknode,
    "Read key node",
    "{;ed;hive;Key hive}{;ed;knode;Key Node}")
{
    ULONG64 KeyHiveAddr = GetUnnamedArgU64(0);
    ULONG64 KeyNodeAddr = GetUnnamedArgU64(1);

    ExtRemoteTyped KeyHive("(nt!_HHIVE *)@$extin", KeyHiveAddr);
    ExtRemoteTyped KeyNode("(nt!_CM_KEY_NODE *)@$extin", KeyNodeAddr);

    RegReadKeyNode(KeyHive, KeyNode);
}

EXT_COMMAND(ms_readkvalue,
    "Read key value",
    "{;ed;hive;Key hive}{;ed;kvalue;Key Value}")
{
    ULONG64 KeyHiveAddr = GetUnnamedArgU64(0);
    ULONG64 KeyValueAddr = GetUnnamedArgU64(1);

    ExtRemoteTyped KeyHive("(nt!_HHIVE *)@$extin", KeyHiveAddr);
    ExtRemoteTyped KeyValue("(nt!_CM_KEY_VALUE *)@$extin", KeyValueAddr);

    RegReadKeyValue(KeyHive, KeyValue);
}


EXT_COMMAND(ms_readkcb,
    "Read key control block",
    "{;ed;kcb;Key Control Block}")
{
    ULONG64 KCB = GetUnnamedArgU64(0);
    ExtRemoteTyped CmKcb("(nt!_CM_KEY_CONTROL_BLOCK *)@$extin", KCB);

    ExtRemoteTyped KeyHive = CmKcb.Field("KeyHive");
    ULONG CellIndex = CmKcb.Field("KeyCell").GetUlong();

    // !reg findkcb \REGISTRY\MACHINE\SYSTEM\MountedDevices
    // !reg findkcb \REGISTRY\MACHINE\SYSTEM

    if (KeyHive.Field("Flat").GetUchar())
    {
        Err("Error: Unsupported/Unexpected mapping (Flat cell)");
        return;
    }

    ULONG64 KeyNodeAddr = RegGetCellPaged(KeyHive, CellIndex);
    ExtRemoteTyped KeyNode("(nt!_CM_KEY_NODE *)@$extin", KeyNodeAddr);

    RegReadKeyNode(KeyHive, KeyNode);

    return;
}

EXT_COMMAND(ms_netstat,
    "Display network information (sockets, connections, ...)",
    "{;e,o;;}")
{
    vector<NETWORK_ENTRY> Sockets = GetSockets();

    Dml("    | <col fg=\"changed\">%-5s</col> | <col fg=\"changed\">%-25s</col> | <col fg=\"changed\">%-25s</col> | "
        "<col fg=\"changed\">%-11s</col> | <col fg=\"changed\">%-16s</col> | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col>\n"
        "    |--------------------------------------------------------------------------------------------------------\n",
        "Proto", "Local Address", "Foreign address", "State", "Process Name", "Pid", "Creation time");
    for each (NETWORK_ENTRY Socket in Sockets)
    {
        SYSTEMTIME SystemTime = { 0 };
        CHAR SrcIpAddress[32];
        CHAR DstIpAddress[32];

        sprintf_s(SrcIpAddress, "%d.%d.%d.%d:%d",
            (ULONG)Socket.Local.IPv4_Addr[0],
            (ULONG)Socket.Local.IPv4_Addr[1],
            (ULONG)Socket.Local.IPv4_Addr[2],
            (ULONG)Socket.Local.IPv4_Addr[3],
            Socket.Local.Port);
        sprintf_s(DstIpAddress, "%d.%d.%d.%d:%d",
            (ULONG)Socket.Remote.IPv4_Addr[0],
            (ULONG)Socket.Remote.IPv4_Addr[1],
            (ULONG)Socket.Remote.IPv4_Addr[2],
            (ULONG)Socket.Remote.IPv4_Addr[3],
            Socket.Remote.Port);

        FileTimeToSystemTime((PFILETIME)&Socket.CreationTime, &SystemTime);
        Dml("    | <col fg=\"emphfg\">%-5s</col> | %25s | %25s | %-11s | %-16s | <link cmd=\"!process %x 1\">0x%04x</link> | %2d/%2d/%4d %2d:%2d:%2d (UTC) |\n",
            GetProtocolType(Socket.Protocol),
            SrcIpAddress, DstIpAddress,
            GetTcbState(Socket.State),
            Socket.ProcessName,
            (ULONG)Socket.ProcessId,
            (ULONG)Socket.ProcessId,
            SystemTime.wDay,
            SystemTime.wMonth,
            SystemTime.wYear,
            SystemTime.wHour,
            SystemTime.wMinute,
            SystemTime.wSecond);
    }
}

EXT_COMMAND(ms_mbr,
    "Scan Master Boot Record (MBR)",
    "{;ed;phys;MBR Physical Address}")
{
    PARTITION_TABLE PartitionTable;
    ULONG BytesRead = 0;

    ULONG64 MBRAddr = GetUnnamedArgU64(0);

    HRESULT hResult = m_Data->ReadPhysical(MBRAddr, &PartitionTable, sizeof(PARTITION_TABLE), &BytesRead);
    if (hResult != S_OK)
    {
        Err("Error: Unable to read BIOS page.\n");
        return;
    }

    Dml("   Disk Signature: {%02x}-{%02x}-{%02x}-{%02x}\n\n",
        PartitionTable.DiskSignature[0],
        PartitionTable.DiskSignature[1],
        PartitionTable.DiskSignature[2],
        PartitionTable.DiskSignature[3]);

    for (UINT i = 0; i < 4; i += 1)
    {
        Dml("   [ Partition %d]\n"
            "     Boot flag:                0x%x\n"
            "     Type:                     0x%x (%s)\n"
            "     Starting Sector(LBA):     0x%x\n"
            "     Starting CHS:             Cylinder=%d, Head=%d, Sector=%d\n"
            "     Ending CHS:               Cylinder=%d, Head=%d, Sector=%d\n"
            "     Size in sectors:          0x%x\n\n",
            i,
            PartitionTable.Entry[i].BootableFlag,
            PartitionTable.Entry[i].PartitionType, GetPartitionType(PartitionTable.Entry[i].PartitionType),
            PartitionTable.Entry[i].StartingLBA,
            PartitionTable.Entry[i].StartingCHS[0], PartitionTable.Entry[i].StartingCHS[1], PartitionTable.Entry[i].StartingCHS[2],
            PartitionTable.Entry[i].EndingCHS[0], PartitionTable.Entry[i].EndingCHS[1], PartitionTable.Entry[i].EndingCHS[2],
            PartitionTable.Entry[i].SizeInSectors);
    }
}

EXT_COMMAND(ms_consoles,
    "Display console command's history ",
    "{;e,o;;}")
{
    ProcessIterator Processes;
    MsProcessObject ProcObject;

    ULONG NumberOfConsoleHandles;

    vector<ULONG64> ConsoleHandles;

    for (Processes.First(); !Processes.IsDone(); Processes.Next())
    {

        ProcObject = Processes.Current();

        // TODO: csrss.exe XP/2003/Vista/
        // csrss.exe

        if (m_Minor >= 7600)
        {
            if (_stricmp(ProcObject.m_CcProcessObject.ImageFileName, "conhost.exe") != 0) continue;

            Dml("   [*] <col fg=\"changed\">Found conhost.exe</col> process (Pid = 0x%x).</col>\n", ProcObject.m_CcProcessObject.ProcessId);

            ProcObject.SwitchContext();
            Execute(".process /p /r 0x%I64X", ProcObject.m_CcProcessObject.ProcessObjectPtr);

            NumberOfConsoleHandles = 1;
            ConsoleHandles.push_back(GetExpression("conhost!gConsoleInformation"));
        }
        else
        {
            if (_stricmp(ProcObject.m_CcProcessObject.ImageFileName, "csrss.exe") != 0) continue;
            Dml("   [*] <col fg=\"changed\">Found csrss.exe</col> process (Pid = 0x%x).</col>\n", ProcObject.m_CcProcessObject.ProcessId);

            ProcObject.SwitchContext();
            Execute(".process /p /r 0x%I64X", ProcObject.m_CcProcessObject.ProcessObjectPtr);

            ULONG64 pNumberOfConsoleHandles = GetExpression("winsrv!NumberOfConsoleHandles");
            ULONG64 pConsoleHandles = GetExpression("winsrv!ConsoleHandles");

            if (!pConsoleHandles || !pNumberOfConsoleHandles) continue;

            if (g_Ext->m_Data->ReadVirtual(pNumberOfConsoleHandles, &NumberOfConsoleHandles, sizeof(ULONG), NULL) != S_OK) continue;

            for (UINT i = 0; i < NumberOfConsoleHandles; i += 1)
            {
                ULONG64 Ptr;
                ReadPointer(pConsoleHandles + (i * m_PtrSize), &Ptr);
                ConsoleHandles.push_back(Ptr);
            }
        }

        for each (ULONG64 gConsoleInformation in ConsoleHandles)
        {
            WCHAR Title[MAX_PATH];

            USHORT HistoryBufferCount, HistoryBufferMax;

            if (!gConsoleInformation) continue;

            ExtRemoteUnTyped ConsoleInfo(gConsoleInformation, "conhost!_CONSOLE_INFORMATION");

            ConsoleInfo.Field("OriginalTitle", TRUE).GetString((PSTR)&Title, sizeof(Title));
            Dml("   -> OriginalTitle = <col fg=\"emphfg\">%S</col>\n", Title);

            ConsoleInfo.Field("Title", TRUE).GetString((PSTR)&Title, sizeof(Title));
            Dml("   -> Title = <col fg=\"emphfg\">%S</col>\n", Title);

            HistoryBufferCount = ConsoleInfo.Field("HistoryBufferCount").GetUshort();
            HistoryBufferMax = ConsoleInfo.Field("HistoryBufferMax").GetUshort();

            Dml("   -> HistoryBufferCount = %x\n", HistoryBufferCount);
            Dml("   -> HistoryBufferMax = %x\n", HistoryBufferMax);

            ULONG64 Rows;
            USHORT ScreenY, ScreenX;

            ScreenY = ConsoleInfo.Field("CurrentScreenBuffer", TRUE).Field("ScreenY").GetUshort();
            ScreenX = ConsoleInfo.Field("CurrentScreenBuffer", TRUE).Field("ScreenX").GetUshort();
            Rows = ConsoleInfo.Field("CurrentScreenBuffer", TRUE).Field("Rows", TRUE).Field("Chars").GetPtr();

            LPWSTR Buffer = (LPWSTR)malloc(ScreenY * ScreenX * sizeof(WCHAR));
            if (g_Ext->m_Data->ReadVirtual(Rows, Buffer, ScreenY * ScreenX * sizeof(WCHAR), NULL) != S_OK) continue;

            ULONG SpaceLinesCount = 0;
            for (UINT y = 0; y < ScreenY; y += 1)
            {
                BOOLEAN isSpaceLine = TRUE;
                for (UINT x = 0; x < ScreenX; x += 1)
                {
                    if (Buffer[(y * ScreenX) + x] != ' ') isSpaceLine = FALSE;
                    Dml("%c", Buffer[(y * ScreenX) + x]);
                }

                Dml("\n");

                if (isSpaceLine) SpaceLinesCount += 1;
                else SpaceLinesCount = 0;

                if (SpaceLinesCount > 3) break;
            }
        }

        ProcObject.RestoreContext();
    }

    return;
}

EXT_COMMAND(ms_credentials,
    "Display user's credentials (based on gentilwiki's mimikatz) ",
    "{;e,o;;}")
{
    Mimikatz();
}

EXT_COMMAND(ms_timers,
    "Display list of KTIMER",
    "{;e,o;;}")
{
    Dml("\n"
        "    |----------------------------|--------------------|--------------------|----------|--------------------|------------------------------------------------------|\n"
        "    | <col fg=\"emphfg\">%-26s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-8s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-6s</col> | <col fg=\"emphfg\">%s</col> |\n"
        "    |----------------------------|--------------------|--------------------|----------|--------------------|------------------------------------------------------|\n",
        "Timer Type", "Timer", "Dpc", "Period", "Deferred Routine", "Hooked", "Module");

    vector<KTIMER> Timers = GetTimers();

    for each (KTIMER Timer in Timers)
    {
        UCHAR Name[512] = { 0 };
        UCHAR TimerType[32] = { 0 };

        switch (Timer.Type)
        {
            case TimerSynchronizationObject:
                strcpy_s((LPSTR)TimerType, sizeof(TimerType), "TimerSynchronizationObject");
                break;
            case TimerNotificationObject:
                strcpy_s((LPSTR)TimerType, sizeof(TimerType), "TimerNotificationObject");
                break;
        }
        Dml("    | %-26s | 0x%016I64X | 0x%016I64X | %8d | 0x%016I64X | <col fg=\"changed\">%-6s</col> | %s\n",
            TimerType, Timer.Timer, Timer.Dpc, Timer.Period, Timer.DeferredRoutine,
            IsPointerHooked(Timer.DeferredRoutine) ? "Hooked" : "",
            GetNameByOffset(Timer.DeferredRoutine, (PSTR)Name, _countof(Name)));
    }
}

EXT_COMMAND(ms_vacbs,
    "Display list of cached VACBs",
    "{;e,o;;}")
{
    vector<VACB_OBJECT> Vacbs = GetVacbs();

    Dml("\n"
        "    |--------------------|--------------------|---|--------------------|\n"
        "    | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%s</col> | <col fg=\"emphfg\">%-18s</col> |\n"
        "    |--------------------|--------------------|---|--------------------|\n",
        "VACB", "Base Address", "V", "Shared Cache Map");

    for each (VACB_OBJECT Vacb in Vacbs)
    {
        Dml("    | 0x%016I64X | 0x%016I64X | %s | 0x%016I64X |\n",
            Vacb.Vacb, Vacb.BaseAddress, Vacb.ValidBase ? "Y" : "-", Vacb.SharedCacheMap);
    }
}

EXT_COMMAND(ms_hivelist,
    "Display list of registry hives",
    "{;e,o;;}"
    "{hive;ed,o;hive;Display information for a given registry hive}"
    "{scan;b,o;scan;Display additional information}")
{
    vector<HIVE_OBJECT> Hives = GetHives();

    BOOLEAN Scan = HasArg("scan");
    CHAR Buffer[128] = { 0 };

    Dml("\n"
        "    |------------------------|----------------------------------------------------------------------------|------------------------|\n"
        "    | <col fg=\"emphfg\">%-22s</col> | <col fg=\"emphfg\">%-74s</col> | <col fg=\"emphfg\">%-64s</col> |\n"
        "    |------------------------|----------------------------------------------------------------------------|------------------------|\n",
        "Hive ('U' = Untrusted)", "Hive Root Path", "File user name");

    for each (HIVE_OBJECT Hive in Hives)
    {
        Dml("    | <link cmd = \"!reg openkeys 0x%I64X\">0x%I64X</link> (%s) | %-74S | %-64S |\n",
            Hive.HivePtr, Hive.HivePtr, Hive.Flags & CM_FLAG_UNTRUSTED ? "U" : "T", Hive.HiveRootPath, Hive.FileUserName);

        if (!Scan) continue;

        if (Hive.GetCellRoutine)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "GetCellRoutine", Hive.GetCellRoutine,
                IsPointerHooked(Hive.GetCellRoutine) ? "Hooked" : "",
                GetNameByOffset(Hive.GetCellRoutine, (PSTR)Buffer, _countof(Buffer)));
        }

        if (Hive.ReleaseCellRoutine)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "ReleaseCellRoutine", Hive.ReleaseCellRoutine,
                IsPointerHooked(Hive.GetCellRoutine) ? "Hooked" : "",
                GetNameByOffset(Hive.ReleaseCellRoutine, (PSTR)Buffer, _countof(Buffer)));
        }

        if (Hive.Allocate)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "Allocate", Hive.Allocate,
                IsPointerHooked(Hive.Allocate) ? "Hooked" : "",
                GetNameByOffset(Hive.Allocate, (PSTR)Buffer, _countof(Buffer)));
        }

        if (Hive.Free)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "Free", Hive.Free,
                IsPointerHooked(Hive.Free) ? "Hooked" : "",
                GetNameByOffset(Hive.Free, (PSTR)Buffer, _countof(Buffer)));
        }

        if (Hive.FileSetSize)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "FileSetSize", Hive.FileSetSize,
                IsPointerHooked(Hive.FileSetSize) ? "Hooked" : "",
                GetNameByOffset(Hive.FileSetSize, (PSTR)Buffer, _countof(Buffer)));
        }

        if (Hive.FileWrite)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "FileWrite", Hive.FileWrite,
                IsPointerHooked(Hive.FileWrite) ? "Hooked" : "",
                GetNameByOffset(Hive.FileWrite, (PSTR)Buffer, _countof(Buffer)));
        }

        if (Hive.FileRead)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "FileRead", Hive.FileRead,
                IsPointerHooked(Hive.FileRead) ? "Hooked" : "",
                GetNameByOffset(Hive.FileRead, (PSTR)Buffer, _countof(Buffer)));
        }

        if (Hive.FileFlush)
        {
            Dml("    \\---| %-24s | %I64X | <col fg=\"changed\">%-6s</col> | <col fg=\"changed\">%s</col> \n",
                "FileFlush", Hive.FileFlush,
                IsPointerHooked(Hive.FileFlush) ? "Hooked" : "",
                GetNameByOffset(Hive.FileFlush, (PSTR)Buffer, _countof(Buffer)));
        }
    }
}

EXT_COMMAND(ms_idt,
    "Display IDT",
    "{;e,o;;}"
    "{base;ed,o;base;Display information for a given idt}")
{
    ULONG64 IdtBase = GetArgU64("base", FALSE);
    vector<IDT_OBJECT> Idts = GetInterrupts(IdtBase);

    Dml("    |-----|-----|--------------------|--------------------------------------------------------|---------|--------|\n"
        "    | <col fg=\"emphfg\">%-3s</col> | <col fg=\"emphfg\">%-3s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-54s</col> | <col fg=\"emphfg\">%-7s</col> | <col fg=\"emphfg\">%-6s</col> |\n"
        "    |-----|-----|--------------------|--------------------------------------------------------|---------|--------|\n",
        "Cre", "Idx", "Address", "Name", "Patched", "Hooked");

    for each (IDT_OBJECT Idt in Idts)
    {
        UCHAR Name[512] = { 0 };

        if (Idt.Entry)
        {
            Dml("    | %3d | %3d | <link cmd = \"u 0x%016I64X L5\">0x%016I64X</link> | %-54s | <col fg=\"changed\">%-7s</col> | <col fg=\"changed\">%-6s</col> |\n",
                Idt.CoreIndex,
                Idt.Index,
                Idt.Entry,
                Idt.Entry,
                GetNameByOffset(Idt.Entry, (PSTR)Name, _countof(Name)),
                Idt.Entry ? "" : "",
                IsPointerHooked(Idt.Entry) ? "Yes" : "No");
        }
    }
}

LPSTR GdtType[] = {
    "Data RO",
    "Data RO Ac",
    "Data RW",
    "Data RW Ac",
    "Data RO E",
    "Data RO EA",
    "Data RW E",
    "Data RW EA",
    "Code EO",
    "Code EO Ac",
    "Code RE",
    "Code RE Ac",
    "Code EO C",
    "Code EO CA",
    "Code RE C",
    "Code RE CA",
    "<Reserved>",
    "TSS16 Avl",
    "LDT",
    "TSS16 Busy",
    "CallGate16",
    "TaskGate",
    "Int Gate16",
    "TrapGate16",
    "<Reserved>",
    "TSS32 Avl",
    "<Reserved>",
    "TSS32 Busy",
    "CallGate32",
    "<Reserved>",
    "Int Gate32",
    "TrapGate32",
    NULL
};

EXT_COMMAND(ms_gdt,
    "Display GDT",
    "{;e,o;;}"
    "{base;ed,o;base;Display information for a given gdt}")
{
    ULONG64 GdtBase = GetArgU64("base", FALSE);
    vector<GDT_OBJECT> Gdts = GetDescriptors(GdtBase);

    Dml("    |-----|-----|--------------------|--------------------------------------------------------|\n"
        "    | <col fg=\"emphfg\">%-3s</col> | <col fg=\"emphfg\">%-3s</col> | <col fg=\"emphfg\">%-32s</col> | <col fg=\"emphfg\">%-18s</col> | <col fg=\"emphfg\">%-54s</col> |\n"
        "    |-----|-----|--------------------|--------------------------------------------------------|\n",
        "Cre", "Idx", "Type", "Address", "Name");

    for each (GDT_OBJECT Gdt in Gdts)
    {
        UCHAR Name[512] = { 0 };

        Dml("    | %3d | %3x | %-32s | 0x%016I64X | %-54s |\n",
            Gdt.CoreIndex,
            Gdt.Index,
            GdtType[Gdt.Type],
            Gdt.Base,
            "None");
    }
}

EXT_COMMAND(ms_malscore,
    "Analyze a memory space and returns a Malware Score Index (MSI) - (based on Frank Boldewin's work)",
    "{;ed;base;Base address}{;ed;size;Memory space size}")
{
    ULONG64 BaseAddress = GetUnnamedArgU64(0);
    ULONG Size = (ULONG)GetUnnamedArgU64(1);

    LPBYTE Buffer = NULL;

    Dml("   [ <col fg=\"changed\">Base:</col> <col fg=\"emphfg\">0x%016I64X</col>\n"
        "   [ <col fg=\"changed\">Size:</col> <col fg=\"emphfg\">0x%X</col>\n",
        BaseAddress, Size);

    Buffer = (LPBYTE)malloc(Size);

    if (ExtRemoteTypedEx::ReadVirtual(BaseAddress, Buffer, Size, NULL) != S_OK)
    {
        Err("Error: Failed to read the memory buffer.\n");
        goto CleanUp;
    }

    ULONG MalwareScoreIndex = GetMalScore(TRUE, BaseAddress, Buffer, Size);

    Dml("   -> <col fg=\"changed\">Malware Score Index (MSI)</col> = <col fg=\"emphfg\">%d</col>\n", MalwareScoreIndex);

CleanUp:
    if (Buffer) free(Buffer);

}

EXT_COMMAND(ms_exqueue,
    "Display Ex queued workers",
    "{;e,o;;}")
{
    GetExQueue();
}

EXT_COMMAND(ms_store,
    "Display information related to the Store Manager (ReadyBoost)",
    "{cache;b,o;cache;Display process information for a cache index}"
    "{log;b,o;log;Display ReadyBoost log}")
{

    StoreManager StrMgr;


    if (HasArg("log"))
    {
        // g_Ext->Dml("Show logs !\n");

        StrMgr.GetSmLogEntries();
    }
    else if (HasArg("cache"))
    {
        ULONG CacheIndex = (ULONG)-1;
        // g_Ext->Dml("Show cache !\n");

        StrMgr.SmiEnumCaches(CacheIndex);
    }
}

EXT_COMMAND(ms_scanndishook,
    "Scan and display suspicious NDIS hooks",
    "")
{
    ULONG64 Address;
    ULONG ulNdisChecked;
    ULONG Status;
    ULONG cbBytesReturned;

    // Create instance of our NDISKD class object
    CNdiskd *myNdiskd = new CNdiskd;

    // Get the WinDBG-style extension APIS.   
    ExtensionApis.nSize = sizeof(ExtensionApis);

    // Initialize ExtensionsApis
    g_Ext->m_Control->GetWindbgExtensionApis64(&ExtensionApis);

    // Get NDIS module base address
    ULONG moduleIdx = 0;
    ULONG64 Base = 0;
    Status = g_Ext->m_Symbols->GetModuleByModuleName(NDIS_NAME, 0, &moduleIdx, &Base);

    // If not loaded then execute ".reload" command to reload ndis.sys symbol
    if (Status == E_INVALIDARG)
    {
        CHAR szCommand[256] = { 0 };

        g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "%s symbol not found. Reloading (.reload) %s\n", NDIS_NAME, NDIS_DRV_NAME);

        sprintf_s(szCommand, sizeof(szCommand), ".reload /f %s", NDIS_DRV_NAME);

        // Execute reload command
        g_Ext->m_Control->Execute(DEBUG_OUTCTL_IGNORE | DEBUG_OUTCTL_NOT_LOGGED, szCommand, DEBUG_EXECUTE_NOT_LOGGED);

        // Make sure the NDIS symbol has been loaded
        Status = g_Ext->m_Symbols->GetModuleByModuleName(NDIS_NAME, 0, &moduleIdx, &Base);

        // NDIS symbol reload failed again?
        if (Status == E_INVALIDARG)
        {
            g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "%s symbol loaded failed!\n", NDIS_NAME);
        }
    }

    if (Base > 0)
    {
        // Save NDIS address range
        myNdiskd->m_ndisBaseAddress = Base;
        myNdiskd->m_ndisEndAddress = Base + utils::getModuleSize(Base);
        g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "%s image: %I64x-%I64x\n", NDIS_NAME, myNdiskd->m_ndisBaseAddress, myNdiskd->m_ndisEndAddress);
    }

    // Read address of ndis!ndisChecked
    Address = GetExpression("ndis!ndisChecked");

    // Got ndisChecked address
    if (Address)
    {
        cbBytesReturned = 0;
        ulNdisChecked = utils::getUlongFromAddress(Address, &cbBytesReturned);

        if (cbBytesReturned == sizeof(ULONG))
        {
            if (ulNdisChecked == 1)
            {
                g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Ndis build: Checked\n");
            }
            else if (ulNdisChecked == 0)
            {
                g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Ndis build: Free\n");
            }

            // Store ndisChecked value
            myNdiskd->m_ndiskdChecked = ulNdisChecked;
        }
    }

    // Read ndis!ndisBuildDate
    Address = GetExpression("ndis!ndisBuildDate");

    // Got ndisBuildDate address
    if (Address)
    {
        ExtRemoteTyped ndisBuildDate("(nt!_UNICODE_STRING*)@$extin", Address);

        // Get the build date in wide character
        utils::getUnicodeString(ndisBuildDate, myNdiskd->m_ndiskdBuildDate, MAX_PROTOCOL_NAME*sizeof(WCHAR));

    }

    // Read ndis!ndisBuildTime
    Address = GetExpression("ndis!ndisBuildTime");

    // Got ndisBuildTime address
    if (Address)
    {
        ExtRemoteTyped ndisBuildTime("(nt!_UNICODE_STRING*)@$extin", Address);

        // Get the build time in wide character
        utils::getUnicodeString(ndisBuildTime, myNdiskd->m_ndiskdBuildTime, MAX_PROTOCOL_NAME*sizeof(WCHAR));
    }

    // Read ndis!ndisBuiltBy
    Address = GetExpression("ndis!ndisBuiltBy");

    // Got ndisBuiltBy address
    if (Address)
    {
        ExtRemoteTyped ndisBuitBy("(nt!_UNICODE_STRING*)@$extin", Address);

        // Get Ndis's author in wide character
        utils::getUnicodeString(ndisBuitBy, myNdiskd->m_ndiskdBuiltBy, MAX_PROTOCOL_NAME*sizeof(WCHAR));
    }

    if (wcslen(myNdiskd->m_ndiskdBuildDate) > 0)
    {
        g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Ndis build date: %ls\n", myNdiskd->m_ndiskdBuildDate);
    }

    if (wcslen(myNdiskd->m_ndiskdBuildTime) > 0)
    {
        g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Ndis build time: %ls\n", myNdiskd->m_ndiskdBuildTime);
    }

    if (wcslen(myNdiskd->m_ndiskdBuiltBy) > 0)
    {
        g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Ndis built by: %ls\n", myNdiskd->m_ndiskdBuiltBy);
    }

    // Instantiate report object
    CReport *reporter = new CReport(g_Ext);

    // Get protocol list
    std::list<CProtocols*> protocolList;
    Dml("<col fg=\"srccmnt\">Scanning network protocol list...</col>\n");
    myNdiskd->GetProtocolList(&protocolList);

    // Walk through protocol list and check the function handlers
    for (std::list<CProtocols*>::iterator it = protocolList.begin(); it != protocolList.end(); ++it)
    {
        std::map<PCSTR, ULONG64> listHandlers;

        (*it)->GetFunctionHandlers(&listHandlers);

        //g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Protocol: %ls\n", (*it)->GetProtocolName());

        // Walk through each function handlers
        for (std::map<PCSTR, ULONG64>::iterator it2 = listHandlers.begin(); it2 != listHandlers.end(); ++it2)
        {
            if (it2->second != NULL)
            {
                DbgPrint("DEBUG: %s:%d:%s Function handler: %s (%I64x)\n", __FILE__, __LINE__, __FUNCTION__, it2->first, it2->second);

                int rule = 0;

                if (/*myNdiskd->IsNdisHook(it2->second) ||*/ myNdiskd->HeuristicHookCheck(it2->second, rule))
                {
                    reporter->ReportHooks("<col fg=\"emphfg\">   Hooked handler:</col> %s (<link cmd=\"u %I64x\">0x%I64X</link>) from protocol <b>%ls</b> (Rule #%d - %s)\n", it2->first, it2->second, it2->second, (*it)->GetProtocolName(), rule, myNdiskd->GetHookType(rule));
                }
            }
        }
    }

    // Get miniport list
    std::list<CAdapters*> miniportlist;
    Dml("<col fg=\"srccmnt\">Scanning network adapter list...\n</col>");
    myNdiskd->GetAdapterList(&miniportlist);

    // Walk through all the adapters and look for hook handlers
    for (std::list<CAdapters*>::iterator it = miniportlist.begin(); it != miniportlist.end(); ++it)
    {
        std::map<PCSTR, ULONG64> listHandlers;

        (*it)->GetFunctionHandlers(&listHandlers);
        //g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Adapter: %ls\n", (*it)->GetAdapterName());

        // Walk through each function handlers
        for (std::map<PCSTR, ULONG64>::iterator it2 = listHandlers.begin(); it2 != listHandlers.end(); ++it2)
        {
            if (it2->second != NULL)
            {
                DbgPrint("DEBUG: %s:%d:%s Function handler: %s (%I64x)\n", __FILE__, __LINE__, __FUNCTION__, it2->first, it2->second);

                int rule = 0;

                if (myNdiskd->IsNdisHook(it2->second) /*|| myNdiskd->HeuristicHookCheck(it2->second, rule)*/)
                {
                    reporter->ReportHooks("<col fg=\"emphfg\">   Hooked handler:</col> %s (<link cmd=\"u %I64x\">0x%I64X</link>) from adapter <b>%ls</b> (Rule #%d - %s)\n", it2->first, it2->second, it2->second, (*it)->GetAdapterName(), rule, myNdiskd->GetHookType(rule));
                }
            }
        }
    }

    // Get open bindings between protocol (eg: TCPIP) and miniport (eg: NIC adapter Intel(R) Gigabit Network Connection)
    std::list<COpenblock*> openblocklist;
    Dml("<col fg=\"srccmnt\">Scanning network binder list...\n</col>");
    myNdiskd->GetOpenblockList(&openblocklist);

    // Walk through all the binders and look for hook handlers
    for (std::list<COpenblock*>::iterator it = openblocklist.begin(); it != openblocklist.end(); ++it)
    {
        std::map<PCSTR, ULONG64> listHandlers;

        (*it)->GetFunctionHandlers(&listHandlers);

        //g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Binder: %ls\n", (*it)->GetBinderName());

        // Walk through each function handlers
        for (std::map<PCSTR, ULONG64>::iterator it2 = listHandlers.begin(); it2 != listHandlers.end(); ++it2)
        {
            if (it2->second != NULL)
            {
                int rule = 0;

                DbgPrint("DEBUG: %s:%d:%s Function handler: %s (%I64x)\n", __FILE__, __LINE__, __FUNCTION__, it2->first, it2->second);

                if ((*it)->IsHandlerHooked(it2->second) || myNdiskd->HeuristicHookCheck(it2->second, rule))
                {
                    reporter->ReportHooks("<col fg=\"emphfg\">   Hooked handler:</col> %s (<link cmd=\"u %I64x\">0x%I64X</link>) from binder <b>%ls</b> (Rule #%d - %s)\n", it2->first, it2->second, it2->second, (*it)->GetBinderName(), rule, myNdiskd->GetHookType(rule));
                }
            }
        }
    }

    // Get minidriver list
    std::list<CMinidriver*> miniDrvList;
    Dml("<col fg=\"srccmnt\">Scanning network mini-driver list...</col>\n");
    myNdiskd->GetMDriverList(&miniDrvList);

    // Walk through all the mini-drivers and look for hook handlers
    for (std::list<CMinidriver*>::iterator it = miniDrvList.begin(); it != miniDrvList.end(); ++it)
    {
        std::map<PCSTR, ULONG64> listHandlers;

        (*it)->GetFunctionHandlers(&listHandlers);

        //g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "Mini-driver: %ls\n", (*it)->GetMDriverName());

        // Walk through each function handlers
        for (std::map<PCSTR, ULONG64>::iterator it2 = listHandlers.begin(); it2 != listHandlers.end(); ++it2)
        {
            if (it2->second != NULL)
            {
                int rule = 0;

                DbgPrint("DEBUG: %s:%d:%s Function handler: %s (%I64x)\n", __FILE__, __LINE__, __FUNCTION__, it2->first, it2->second);

                if ((*it)->IsHandlerHooked(it2->second) || myNdiskd->HeuristicHookCheck(it2->second, rule))
                {
                    reporter->ReportHooks("<col fg=\"emphfg\">   Hooked handler:</col> %s (<link cmd=\"u %I64x\">0x%I64X</link>) from adapter <b>%ls</b> (Rule #%d - %s)\n", it2->first, it2->second, it2->second, (*it)->GetMDriverName(), rule, myNdiskd->GetHookType(rule));
                }
            }
        }
    }

    // Object instances cleanup here
    // Cleanup Ndiskd object.
    delete myNdiskd;

    // Cleanup protocols object
    for (std::list<CProtocols*>::iterator it = protocolList.begin(); it != protocolList.end(); ++it)
    {
        delete *it;
    }

    // Cleanup adapters object
    for (std::list<CAdapters*>::iterator it = miniportlist.begin(); it != miniportlist.end(); ++it)
    {
        delete *it;
    }

    // Cleanup binder object
    for (std::list<COpenblock*>::iterator it = openblocklist.begin(); it != openblocklist.end(); ++it)
    {
        delete *it;
    }

    // Cleanup mini-driver object
    for (std::list<CMinidriver*>::iterator it = miniDrvList.begin(); it != miniDrvList.end(); ++it)
    {
        delete *it;
    }
}

EXT_COMMAND(ms_fixit,
    "Reset segmentation in WinDbg (Fix \"16.kd>\")",
    "{;e,o;;}")
{
    Execute(".segmentation -X");
}

EXT_COMMAND(ms_verbose,
    "Turn verbose mode on/off",
    "{;e,o;;}")
{
    g_Verbose = !g_Verbose;
}

EXT_COMMAND(ms_checkcodecave,
            "Look for used code cave",
            "{;e,o;;}"
            "{pid;ed,d=0;pid;Process Id}")
{
    ULONG64 ProcessId = GetArgU64("pid", FALSE);
    ProcessArray CachedProcessList = GetProcesses(ProcessId, PROCESS_DLLS_FLAG | PROCESS_DLL_EXPORTS_FLAG);

    if (ProcessId) {
        Dml(" [-] Checking process id: 0x%llX\n", ProcessId);
    }
    else {
        Dml(" [-] Checking all available processes.\n");
    }

    if (g_Verbose) Dml("Head: 0x%llX\n", ExtNtOsInformation::GetKernelProcessListHead());

    for each (MsProcessObject ProcObject in CachedProcessList)
    {
        if (ProcessId) {
            if (ProcessId != ProcObject.m_CcProcessObject.ProcessId) continue;
        }

        if (!ProcObject.SwitchContext()) {
            if (g_Verbose) Dml(" [-] Can't switch context.\n");
            continue;
        }

        if (g_Verbose) Dml("Looking inside the executable sections...\n");
        for each (MsPEImageFile::CACHED_SECTION_INFO SectionHeader in ProcObject.m_CcSections) {
            if (g_Verbose)  Dml(" [!] Section: %s\n", SectionHeader.Name);
            ULONG CorruptionScore = 0;
            if (ULONG Offset = HasUsedCodeCave(ProcObject.m_ImageBase, &ProcObject.m_CcSections, &SectionHeader, &CorruptionScore)) {
                Dml(" [!][Score = %5d] (Pid=0x%llX, Name=%s) corruptioned detected at 0x%llX (0x%x) inside \"%s\" section.\n",
                    CorruptionScore,
                    ProcObject.m_CcProcessObject.ProcessId,
                    ProcObject.m_CcProcessObject.ImageFileName,
                    ProcObject.m_ImageBase + Offset,
                    Offset,
                    SectionHeader.Name);
            }
        }

        if (g_Verbose) Dml("Looking inside the dlls sections...\n");
        for each (MsDllObject DllObj in ProcObject.m_DllList) {
            if (g_Verbose)  Dml("   [!] Dll: %S\n", DllObj.mm_CcDllObject.DllName);
            for each (MsPEImageFile::CACHED_SECTION_INFO SectionHeader in DllObj.m_CcSections) {
                if (g_Verbose)  Dml("   [!] Dll: %S (section: %s)\n", DllObj.mm_CcDllObject.DllName, SectionHeader.Name);
                ULONG CorruptionScore = 0;
                if (ULONG Offset = HasUsedCodeCave(DllObj.m_ImageBase, &DllObj.m_CcSections, &SectionHeader, &CorruptionScore)) {
                    if (CorruptionScore > 8) {
                        Dml(" [!][Score = %5d] (Pid=0x%llX, Name=%s, Dll=%S) corruption detected at <link cmd=\"db %I64x\">0x%I64X</link> (0x%x) inside \"%s\" section.\n",
                            CorruptionScore,
                            ProcObject.m_CcProcessObject.ProcessId,
                            ProcObject.m_CcProcessObject.ImageFileName,
                            DllObj.mm_CcDllObject.DllName,
                            DllObj.m_ImageBase + Offset,
                            DllObj.m_ImageBase + Offset,
                            Offset,
                            SectionHeader.Name);
                    }
                }
            }
        }

        ProcObject.RestoreContext();
    }
}