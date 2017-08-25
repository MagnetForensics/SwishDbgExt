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

    - Process.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "stdafx.h"
#include "SwishDbgExt.h"
#include "Process.h"

VOID
GetLX(
    VOID
) {
    vector<ULONG64> ListNodes;
    vector<ULONG64> SessionListNodes;
    vector<ULONG64> LxProcessGroupListNodes;
    vector<ULONG64> LxThreadGroupListNodes;
    ULONG64 ListNodeOffset;
    ULONG64 SessionListNodeOffset;
    ULONG64 LxProcessGroupListNodeOffset;
    ULONG64 LxThreadGroupListNodeOffset;
    ULONG64 LxGlobal;
    ULONG ProcessorType;
    ULONG PlateformId, Major, Minor, ServicePackNumber;

    if (g_Ext->m_Control->GetActualProcessorType(&ProcessorType) != S_OK) goto CleanUp;
    if (g_Ext->m_Control->GetSystemVersion(&PlateformId, &Major, &Minor, NULL, NULL, NULL, &ServicePackNumber, NULL, NULL, NULL) != S_OK) goto CleanUp;

    if ((Minor < 14393) && (ProcessorType != IMAGE_FILE_MACHINE_AMD64)) {
        g_Ext->Dml("This platform does not have Linux Subsystem.\n");
        goto CleanUp;
    }

    if (g_Ext->m_Symbols->GetOffsetByName("lxcore!LxGlobal", &LxGlobal) != S_OK) goto CleanUp;
    if (!LxGlobal) goto CleanUp;

    g_Ext->Dml("\n\tWindows Subsystem for Linux Overview.\n");

    {
        ExtRemoteUnTyped GlobalData(LxGlobal, "lx!_LX_GLOBAL_DATA");

        USHORT NTCS = GlobalData.Field("NTCSignature").GetUshort();
        if (NTCS != 0x15c1) {
            g_Ext->Warn("WARNING: NTCS is different than 0x15c1 (value = 0x%x)\n", NTCS);
        }

        DbgPrint("LxGlobal = 0x%I64X...\n", LxGlobal);
        DbgPrint("InstanceListOffset = 0x%I64X (Flink = 0x%I64X)\n", GlobalData.Field("InstanceListOffset").GetPointerTo(), GlobalData.Field("InstanceListOffset.Flink").GetPtr());

        ExtRemoteTypedList List(GlobalData.Field("InstanceListOffset").GetPointerTo(), "nt!_LIST_ENTRY", "Flink");

        for (List.StartHead(); List.HasNode(); List.Next())
        {
            GUID Guid = { 0 };

            ListNodeOffset = List.GetNodeOffset();

            DbgPrint("\tLX_INSTANCE = 0x%p\n", ListNodeOffset);

            if (find(ListNodes.rbegin(), ListNodes.rend(), ListNodeOffset) != ListNodes.rend()) {

                break;
            }

            ListNodes.push_back(ListNodeOffset);

            ULONG64 LxInstanceHead = ListNodeOffset - GetFieldOffset("lx!_LX_INSTANCE", "I_ListOffset.Flink");
            ExtRemoteUnTyped Instance(LxInstanceHead, "lx!_LX_INSTANCE");
            g_Ext->Dml("\t<b><u>Instance 0x%I64X</u></b>\n", Instance.GetPointerTo());

            if (g_Ext->m_Data->ReadVirtual(Instance.Field("I_GuidOffset").GetPointerTo(), &Guid, sizeof(GUID), NULL) != S_OK) goto CleanUp;
            g_Ext->Dml("\tGUID: {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\n",
                Guid.Data1, Guid.Data2, Guid.Data3,
                Guid.Data4[0], Guid.Data4[1], Guid.Data4[2], Guid.Data4[3],
                Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7]);

            g_Ext->Dml("\tState:            (%d) %s\n", Instance.Field("I_StateOffset").GetPtr(), !Instance.Field("I_StateOffset").GetPtr() ? "[CREATED]" : "[STARTED]");
            g_Ext->Dml("\tCreation Flags:   %08lX\n", Instance.Field("I_FlagsOffset").GetUlong());
            g_Ext->Dml("\tGlobalData:       0x%I64X\n", Instance.Field("I_GlobalDataOffset").GetPtr());

            g_Ext->Dml("\tRoot Handle:      <link cmd=\"!handle %lx 2 4\">%lx</link>\n", Instance.Field("I_RootHandleOffset").GetPtr(), Instance.Field("I_RootHandleOffset").GetPtr());
            g_Ext->Dml("\tTemp Handle:      <link cmd=\"!handle %lx 2 4\">%lx</link>\n", Instance.Field("I_TempHandleOffset").GetPtr(), Instance.Field("I_TempHandleOffset").GetPtr());
            g_Ext->Dml("\tJob Handle:       <link cmd=\"!handle %lx 2 4\">%lx</link>\n", Instance.Field("I_JobHandleOffset").GetPtr(), Instance.Field("I_JobHandleOffset").GetPtr());

            g_Ext->Dml("\tToken:            <link cmd=\".foreach /pS 0n28 /ps 1000 (place { !handle %lx 2 4 }) { !token place -n }\">%lx</link>\n", Instance.Field("I_TokenHandleOffset").GetPtr(), Instance.Field("I_TokenHandleOffset").GetPtr());
            g_Ext->Dml("\tEvent Handle:     <link cmd=\"!handle %lx 2 4\">%lx</link>\n\n", Instance.Field("I_EventHandleOffset").GetPtr(), Instance.Field("I_EventHandleOffset").GetPtr());
            g_Ext->Dml("\tMap Paths (%d):    0x%P\n", Instance.Field("I_PathCountOffset").GetUlong(), Instance.Field("I_PathsOffset").GetPtr());

            g_Ext->Dml("\tVFS Context:      0x%P\n", Instance.Field("I_VfsContextOffset").GetPtr());
            g_Ext->Dml("\tMemory Flags:     0x%llX\n\n", Instance.Field("I_MemoryFlagsOffset").GetPtr());
            g_Ext->Dml("\tLast PID:         %d\n", Instance.Field("I_LastPidOffset").GetPtr());
            g_Ext->Dml("\tThread Groups:    %d\n", Instance.Field("I_GroupCountOffset").GetPtr());

            ExtRemoteTypedList SessionList(Instance.Field("I_SessionListOffset").GetPointerTo(), "nt!_LIST_ENTRY", "Flink");

            for (SessionList.StartHead(); SessionList.HasNode(); SessionList.Next()) {

                SessionListNodeOffset = SessionList.GetNodeOffset();

                if (find(SessionListNodes.rbegin(), SessionListNodes.rend(), SessionListNodeOffset) != SessionListNodes.rend()) {

                    break;
                }

                SessionListNodes.push_back(SessionListNodeOffset);

                DbgPrint("\t\t_LX_SESSION = 0x%p\n", SessionListNodeOffset);
                ULONG64 LxSessionHead = SessionListNodeOffset - GetFieldOffset("lx!_LX_SESSION", "S_ListOffset.Flink");
                DbgPrint("\t\tLxSessionHead = 0x%I64X\n", LxSessionHead);
                ExtRemoteUnTyped LxSession(LxSessionHead, "lx!_LX_SESSION");
                g_Ext->Dml("\t\t<b><u>Session 0x%I64X</u></b>\n", LxSession.GetPointerTo());

                g_Ext->Dml("\t\tInstance:         0x%I64X\n", LxSession.Field("S_InstanceOffset").GetPtr());
                g_Ext->Dml("\t\tConsole inode:    0x%I64X\n", LxSession.Field("S_ConInodeOffset").GetPtr());
                g_Ext->Dml("\t\tForeground PID:   %d\n", (ULONG)LxSession.Field("S_FgPidOffset").GetPtr());

                ExtRemoteTypedList LxProcessGroupList(LxSession.Field("S_GroupListOffset").GetPointerTo(), "nt!_LIST_ENTRY", "Flink");

                for (LxProcessGroupList.StartHead(); LxProcessGroupList.HasNode(); LxProcessGroupList.Next()) {

                    LxProcessGroupListNodeOffset = LxProcessGroupList.GetNodeOffset();

                    if (find(LxProcessGroupListNodes.rbegin(), LxProcessGroupListNodes.rend(), LxProcessGroupListNodeOffset) != LxProcessGroupListNodes.rend()) {

                        break;
                    }

                    LxProcessGroupListNodes.push_back(LxProcessGroupListNodeOffset);

                    DbgPrint("\t\t\t_LX_PROCESSGROUP = 0x%p\n", LxProcessGroupListNodeOffset);
                    ULONG64 LxProcessGroupHead = LxProcessGroupListNodeOffset - GetFieldOffset("lx!_LX_PROCESSGROUP", "PG_ListOffset.Flink");
                    DbgPrint("\t\t\tLxProcessGroupHead = 0x%I64X\n", LxProcessGroupHead);
                    ExtRemoteUnTyped LxProcessGroup(LxProcessGroupHead, "lx!_LX_PROCESSGROUP");
                    g_Ext->Dml("\t\t\t<b><u>Process Group 0x%I64X</u></b>\n", LxProcessGroup.GetPointerTo());
                    g_Ext->Dml("\t\t\tInstance:      0x%P\n", LxProcessGroup.Field("PG_InstanceOffset").GetPtr());
                    g_Ext->Dml("\t\t\tSession:       0x%P\n", LxProcessGroup.Field("PG_SessionOffset").GetPtr());

                    ExtRemoteTypedList LxThreadGroupList(LxProcessGroup.Field("PG_GroupListOffset").GetPointerTo(), "nt!_LIST_ENTRY", "Flink");

                    for (LxThreadGroupList.StartHead(); LxThreadGroupList.HasNode(); LxThreadGroupList.Next()) {

                        LxThreadGroupListNodeOffset = LxThreadGroupList.GetNodeOffset();

                        if (find(LxThreadGroupListNodes.rbegin(), LxThreadGroupListNodes.rend(), LxThreadGroupListNodeOffset) != LxThreadGroupListNodes.rend()) {

                            break;
                        }

                        LxThreadGroupListNodes.push_back(LxThreadGroupListNodeOffset);

                        DbgPrint("\t\t\t\t_LX_THREADGROUP = 0x%p\n", LxThreadGroupListNodeOffset);
                        ULONG64 LxThreadGroupHead = LxThreadGroupListNodeOffset - GetFieldOffset("lx!_LX_THREADGROUP", "TG_ListOffset.Flink");
                        DbgPrint("\t\t\t\tLxProcessGroupHead = 0x%I64X\n", LxThreadGroupHead);
                        ExtRemoteUnTyped LxThreadGroup(LxThreadGroupHead, "lx!_LX_THREADGROUP");
                        g_Ext->Dml("\t\t\t\t<b><u>Thread Group 0x%I64X</u></b>\n", LxThreadGroup.GetPointerTo());

                        WCHAR BinaryPath[MAX_PATH] = { 0 };
                        ExtRemoteTyped BinaryPathTyped("(nt!_UNICODE_STRING*)@$extin", LxThreadGroup.Field("TG_PathOffset").GetPointerTo());
                        ExtRemoteTypedEx::GetUnicodeString(BinaryPathTyped, (PWSTR)BinaryPath, sizeof(BinaryPath));
                        g_Ext->Dml("\t\t\t\tBinary Path:           %S\n", BinaryPath);
                        g_Ext->Dml("\t\t\t\tThread(s):             %d\n", LxThreadGroup.Field("TG_ThreadCountOffset").GetUlong());
                        g_Ext->Dml("\t\t\t\tOwner Process Group:   0x%P\n", LxThreadGroup.Field("TG_ProcGroupOffset").GetPtr());
                        g_Ext->Dml("\t\t\t\tFlags:                 0x%08lX\n", LxThreadGroup.Field("TG_FlagsOffset").GetUlong());
                        g_Ext->Dml("\t\t\t\tMain Thread:           0x%P\n", LxThreadGroup.Field("TG_MainThreadOffset").GetPtr());
                        ULONG FileHandle = 0;
                        if (g_Ext->m_Data->ReadVirtual(Instance.Field("TG_FileOffset").GetPtr(), &FileHandle, sizeof(ULONG), NULL) == S_OK) {
                            g_Ext->Dml("\t\t\t\tFile Handle:           0x%08lX\n", Instance.Field("TG_FileOffset").GetPtr());
                        }
                        ULONG ArgLen = LxThreadGroup.Field("TG_ArgsSizeOffset").GetUlong();
                        ULONG64 ArgPtr = LxThreadGroup.Field("TG_ArgumentsOffset").GetPtr();
                        g_Ext->Dml("\t\t\t\tArguments (%03d bytes): 0x%P\n", ArgLen, ArgPtr);
                        if (ArgLen) {
                            CHAR Arguments[MAX_PATH] = { 0 };
                            if (g_Ext->m_Data->ReadVirtual(ArgPtr, Arguments, min(ArgLen, sizeof(Arguments)) , NULL) == S_OK) {
                                g_Ext->Dml("\t\t\t\tArguments (string):     %s\n", Arguments);
                            }
                        }

                        ULONG64 LxProcessHead = LxThreadGroup.Field("TG_ProcOffset").GetPtr();
                        DbgPrint("\t\t\t\t\t_LX_PROCESS = 0x%p\n", LxProcessHead);

                        ExtRemoteUnTyped LxProcess(LxProcessHead, "lx!_LX_PROCESS");
                        g_Ext->Dml("\t\t\t\t\t<b><u>Process 0x%I64X</u></b>\n", LxProcess.GetPointerTo());
                        g_Ext->Dml("\t\t\t\t\tInstance:            0x%P\n", LxProcess.Field("P_InstanceOffset").GetPtr());
                        g_Ext->Dml("\t\t\t\t\tNT Process Object:   0x%P\n", LxProcess.Field("P_ProcObjectOffset").GetPtr());
                        g_Ext->Dml("\t\t\t\t\tNT Process Handle:   0x%P\n", LxProcess.Field("P_ProcHandleOffset").GetPtr());
                        g_Ext->Dml("\t\t\t\t\tVDSO Address:        0x%P\n", LxProcess.Field("P_VdsoOffset").GetPtr());
                        g_Ext->Dml("\t\t\t\t\tStack Address:       0x%P\n", LxProcess.Field("P_StackOffset").GetPtr());
                    }
                }
            }
        }
    }

CleanUp:
    return;
}