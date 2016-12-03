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

map<PVOID, ULONG> g_References;

//
// User-Mode Modules (DLLs)
//
ModuleIterator::ModuleIterator(
    ULONG64 ModuleHead
    ) :
    m_ModuleListHead(ModuleHead),
    m_ModuleList(m_ModuleListHead, "nt!_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")
{
    m_ModuleList.StartHead();
}

VOID
ModuleIterator::First()
{
    m_ModuleList.StartHead();
}

ExtRemoteTyped
ModuleIterator::Current(
VOID
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
    return m_ModuleList.GetTypedNodePtr();
}

VOID
ModuleIterator::Next(
VOID
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
    //
    // Could also use something like:
    // m_Current = m_Current.Field("MmProcessLinks");
    // 

    m_ModuleList.Next();
}

VOID
ModuleIterator::Prev(
VOID
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
    m_ModuleList.Prev();
}

BOOLEAN
ModuleIterator::IsDone(
VOID
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
    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Current().GetPtr() = 0x%llX\n", __FILE__, __FUNCTIONW__, __LINE__, Current().GetPtr());

    return !m_ModuleList.HasNode();
}

VOID
MsDllObject::Set(
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
    RtlZeroMemory(&mm_CcDllObject, sizeof(mm_CcDllObject));

    if (m_TypedObject.GetPtr()) {
        m_ImageBase = m_TypedObject.Field("DllBase").GetPtr();
        m_ImageSize = m_TypedObject.Field("SizeOfImage").GetUlong();

        ExtRemoteTypedEx::GetUnicodeString(m_TypedObject.Field("FullDllName"),
            (PWSTR)&mm_CcDllObject.FullDllName,
            sizeof(mm_CcDllObject.FullDllName));

        ExtRemoteTypedEx::GetUnicodeString(m_TypedObject.Field("BaseDllName"),
            (PWSTR)&mm_CcDllObject.DllName,
            sizeof(mm_CcDllObject.DllName));
    }
}

//
// Process
//
ProcessIterator::ProcessIterator(
    PROCESS_LINKS_TYPE ProcessLinksType
    )
    : m_ProcessHead(ExtNtOsInformation::GetKernelProcessListHead()),
    m_ProcessList(m_ProcessHead,
    "nt!_EPROCESS",
    "ActiveProcessLinks")
/*++

Routine Description:

    Description.

Arguments:

     - 

Return Value:

    None.

--*/
{
    m_LinksType = ProcessLinksType;

    m_ProcessList.StartHead();

    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] m_ProcessHead = 0x%llX\n", __FILE__, __FUNCTIONW__, __LINE__, m_ProcessHead);
    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Process List Node = 0x%llX\n", __FILE__, __FUNCTIONW__, __LINE__, m_ProcessList.GetNodeOffset());

    if (ProcessLinksType == ProcessLinksMmType)
    {
        if ((m_ProcessList.GetTypedNodePtr().HasField("MmProcessLinks")))
        {
            ExtRemoteTypedList m_MmProcessList(m_ProcessList.GetTypedNodePtr().Field("MmProcessLinks").GetPointerTo().GetPtr(),
                "nt!_EPROCESS",
                "MmProcessLinks");

            m_ProcessList = m_MmProcessList;

            m_ProcessList.StartHead();
        }
    }
}

VOID
ProcessIterator::First(
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
    m_ProcessList.StartHead();
}

ExtRemoteTyped
ProcessIterator::Current(
VOID
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
    return m_ProcessList.GetTypedNodePtr();
}

ExtRemoteTyped
ProcessIterator::CurrentNode(
VOID
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
    return m_ProcessList.GetTypedNode();
}

VOID
ProcessIterator::Next(
    VOID
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
    //
    // Could also use something like:
    // m_Current = m_Current.Field("MmProcessLinks");
    // 

    m_ProcessList.Next();
}

VOID
ProcessIterator::Prev(
    VOID
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
    m_ProcessList.Prev();
}

BOOLEAN
ProcessIterator::IsDone(
    VOID
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
    BOOLEAN bIsDone = TRUE;

    // Pcb.Header.Type == 3 (Process)

    // if (g_Verbose) g_Ext->Dml("Current().m_Offset = 0x%llX\n", Current().m_Offset);
    // if (g_Verbose) g_Ext->Dml("Get Node Offset = 0x%llX\n", m_ProcessList.GetNodeOffset());
    // if (g_Verbose) g_Ext->Dml("Get Node Offset = 0x%llX\n", Current().GetPtr());

    if (Current().GetPtr()) {
        // if (g_Verbose) g_Ext->Dml("Current().Field(Pcb).Field(Header).Field(Type) = 0x%d\n", Current().Field("Pcb").Field("Header").Field("Type").GetChar());
        // if (g_Verbose) g_Ext->Dml("Current().Field(UniqueProcessId).GetPtr() = 0x%llX\n", Current().Field("UniqueProcessId").GetPtr());
        // if (g_Verbose) g_Ext->Dml("m_ProcessList.HasNode() %d\n", m_ProcessList.HasNode());

        bIsDone = (Current().Field("Pcb").Field("Header").Field("Type").GetChar() != 3) || (Current().Field("UniqueProcessId").GetPtr() == 0) || !m_ProcessList.HasNode();
    }

    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Leaving... (Return value = %d)\n", __FILE__, __FUNCTIONW__, __LINE__, bIsDone);

    return bIsDone;
}

BOOLEAN
MsProcessObject::RestoreContext(
    VOID
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
    BOOLEAN Result = FALSE;

    if (m_ProcessDataOffset) g_Ext->m_System2->SetImplicitProcessDataOffset(m_ProcessDataOffset);
    m_ProcessDataOffset = 0; // Synchronous, so we don't need a lock.

    Result = TRUE;

    return Result;
}

BOOLEAN
MsProcessObject::SwitchContext(
    VOID
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
    BOOLEAN Result = FALSE;

    //
    // Save, and change the current process.
    //
    if (g_Ext->m_System2->GetImplicitProcessDataOffset(&m_ProcessDataOffset) != S_OK) goto CleanUp;
    if (g_Ext->m_System2->SetImplicitProcessDataOffset(m_CcProcessObject.ProcessObjectPtr) != S_OK) goto CleanUp;

    Result = TRUE;

CleanUp:
    return Result;
}

BOOLEAN
MsProcessObject::GetDlls(
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
    BOOLEAN Result = TRUE;
    ULONG64 Peb = m_TypedObject.Field("Peb").GetPtr();

    if (Peb && IsValid(Peb) && IsValid(m_TypedObject.Field("Peb").Field("Ldr").GetPtr())) {

        ULONG64 Head = m_TypedObject.Field("Peb").Field("Ldr").Field("InLoadOrderModuleList").GetPointerTo().GetPtr();

        if (IsValid(Head)) {

            ModuleIterator Dlls(Head);

            for (Dlls.First(); !Dlls.IsDone(); Dlls.Next()) {

                MsDllObject Object = Dlls.Current();
                m_DllList.push_back(Object);
            }
        }
    }

    //
    // Wow64
    //

    if (m_TypedObject.HasField("Wow64Process") && (m_TypedObject.Field("Wow64Process").GetPtr() != 0)) {

        PEB_LDR_DATA PebLdrData = {0};
        LDR_DATA_TABLE_ENTRY32 LdrDataTableEntry = {0};
        ExtRemoteTyped Peb32("(nt!_PEB32 *)@$extin", m_TypedObject.Field("Wow64Process").GetPtr());

        if (IsValid(Peb32.GetPtr())) {

            ULONG64 Ldr = Peb32.Field("Ldr").GetUlong();

            if (g_Ext->m_Data->ReadVirtual(Ldr, &PebLdrData, sizeof(PebLdrData), NULL) != S_OK) goto CleanUp;

            if (g_Ext->m_Data->ReadVirtual(PebLdrData.InLoadOrderModuleList.Flink, &LdrDataTableEntry, sizeof(LdrDataTableEntry), NULL) != S_OK) goto CleanUp;

            while (PebLdrData.InLoadOrderModuleList.Flink != LdrDataTableEntry.InLoadOrderLinks.Flink)
            {
                MsDllObject Object;

                if (LdrDataTableEntry.InLoadOrderLinks.Flink == 0) break;
                if (LdrDataTableEntry.DllBase == 0) break;
                if (LdrDataTableEntry.SizeOfImage == 0) break;

                Object.mm_CcDllObject.IsWow64 = TRUE;

                Object.m_ImageBase = LdrDataTableEntry.DllBase;
                Object.m_ImageSize = LdrDataTableEntry.SizeOfImage;

                if (g_Ext->m_Data->ReadVirtual(LdrDataTableEntry.BaseDllName.Buffer,
                                               (PWSTR)&Object.mm_CcDllObject.DllName,
                                               LdrDataTableEntry.BaseDllName.Length,
                                               NULL) != S_OK) break;

                if (g_Ext->m_Data->ReadVirtual(LdrDataTableEntry.FullDllName.Buffer,
                                               (PWSTR)&Object.mm_CcDllObject.FullDllName,
                                               LdrDataTableEntry.FullDllName.Length,
                                               NULL) != S_OK) break;

                m_DllList.push_back(Object);

                if (g_Ext->m_Data->ReadVirtual(LdrDataTableEntry.InLoadOrderLinks.Flink, &LdrDataTableEntry, sizeof(LdrDataTableEntry), NULL) != S_OK) goto CleanUp;
            }
        }
    }

CleanUp:
    return Result;
}

BOOLEAN
MsProcessObject::GetHandles(
    ULONG64 InTableCode
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
    ULONG64 TableCode = 0;
    
    if (InTableCode) TableCode = InTableCode;
    else TableCode = m_TypedObject.Field("ObjectTable").Field("TableCode").GetPtr();

    ULONG Level = (ULONG)(TableCode & 7);
    ULONG64 Table = TableCode & ~7;

    ULONG PtrSize = g_Ext->m_PtrSize;

    ULONG HandleTableEntrySize = GetTypeSize("nt!_HANDLE_TABLE_ENTRY");

    BOOLEAN Result = FALSE;

    LPWSTR ObjName = NULL;

    ULONG HandleIndex = 4;

    ULONG BodyOffset = 0;
    GetFieldOffset("nt!_OBJECT_HEADER", "Body", &BodyOffset);

    switch (Level)
    {
        case 3:
            for (UINT l = 0; l < (PAGE_SIZE / PtrSize); l += 1)
            {
                ULONG64 Ptr2;
                if (ReadPointersVirtual(1, TableCode + (l * PtrSize), &Ptr2) != S_OK) goto CleanUp;
                if (!Ptr2) continue;

                for (UINT k = 0; k < (PAGE_SIZE / PtrSize); k += 1)
                {
                    ULONG64 Ptr1;
                    if (ReadPointersVirtual(1, Ptr2 + (k * PtrSize), &Ptr1) != S_OK) goto CleanUp;
                    if (!Ptr1) continue;

                    for (UINT j = 0; j < (PAGE_SIZE / PtrSize); j += 1)
                    {
                        ULONG64 Ptr;
                        if (ReadPointersVirtual(1, Ptr1 + (j * PtrSize), &Ptr) != S_OK) goto CleanUp;
                        if (!Ptr) continue;

                        for (UINT i = 1; i < (PAGE_SIZE / HandleTableEntrySize); i += 1)
                        {
                            HANDLE_OBJECT HandleObj = { 0 };

                            ExtRemoteTyped TableEntry("(nt!_HANDLE_TABLE_ENTRY *)@$extin", Ptr + (i * HandleTableEntrySize));

                            ULONG64 Object = (TableEntry.Field("Object").GetPtr() & ~1);
                            if (!Object) continue;

                            Object += BodyOffset;

                            ObReadObject(Object, &HandleObj);
                            HandleObj.Handle = HandleIndex;

                            m_Handles.push_back(HandleObj);
                        }
                    }
                }
            }
        break;
        case 2:
            for (UINT k = 0; k < (PAGE_SIZE / PtrSize); k += 1)
            {
                ULONG64 Ptr1;
                if (ReadPointersVirtual(1, TableCode + (k * PtrSize), &Ptr1) != S_OK) goto CleanUp;
                if (!Ptr1) continue;

                for (UINT j = 0; j < (PAGE_SIZE / PtrSize); j += 1)
                {
                    ULONG64 Ptr;
                    if (ReadPointersVirtual(1, Ptr1 + (j * PtrSize), &Ptr) != S_OK) goto CleanUp;
                    if (!Ptr) continue;

                    for (UINT i = 1; i < (PAGE_SIZE / HandleTableEntrySize); i += 1)
                    {
                        HANDLE_OBJECT HandleObj = { 0 };

                        ExtRemoteTyped TableEntry("(nt!_HANDLE_TABLE_ENTRY *)@$extin", Ptr + (i * HandleTableEntrySize));

                        ULONG64 Object = (TableEntry.Field("Object").GetPtr() & ~1);
                        if (!Object) continue;
                        Object += BodyOffset;

                        ObReadObject(Object, &HandleObj);
                        HandleObj.Handle = HandleIndex;

                        m_Handles.push_back(HandleObj);
                    }
                }
            }
        break;
        case 1:
            for (UINT j = 0; j < (PAGE_SIZE / PtrSize); j += 1)
            {
                ULONG64 Ptr;
                if (ReadPointersVirtual(1, Table + (j * PtrSize), &Ptr) != S_OK) goto CleanUp;
                if (!Ptr) continue;

                for (UINT i = 1; i < (PAGE_SIZE / HandleTableEntrySize); i += 1, HandleIndex += 4)
                {
                    HANDLE_OBJECT HandleObj = { 0 };

                    ExtRemoteTyped TableEntry("(nt!_HANDLE_TABLE_ENTRY *)@$extin", Ptr + (i * HandleTableEntrySize));

                    ULONG64 Object = (TableEntry.Field("Object").GetPtr() & ~1);
                    if (!Object) continue;
                    Object += BodyOffset;

                    ObReadObject(Object, &HandleObj);
                    HandleObj.Handle = HandleIndex;

                    m_Handles.push_back(HandleObj);
                }
            }
        break;
        case 0:
            for (UINT i = 1; i < (PAGE_SIZE / HandleTableEntrySize); i += 1)
            {
                HANDLE_OBJECT HandleObj = { 0 };

                ExtRemoteTyped TableEntry("(nt!_HANDLE_TABLE_ENTRY *)@$extin", Table + (i * HandleTableEntrySize));

                ULONG64 Object = (TableEntry.Field("Object").GetPtr() & ~1);
                if (!Object) continue;
                Object += BodyOffset;

                ObReadObject(Object, &HandleObj);
                HandleObj.Handle = HandleIndex;

                m_Handles.push_back(HandleObj);
            }
        break;
    }

    Result = TRUE;

CleanUp:
    if (ObjName) free(ObjName);

    ReleaseObjectTypeTable();

    return Result;
}

VOID
MsProcessObject::Set(
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
    ULONG64 Peb;

    RtlZeroMemory(&m_CcProcessObject, sizeof(m_CcProcessObject));

    m_CcProcessObject.ProcessId = m_TypedObject.Field("UniqueProcessId").GetPtr();
    m_CcProcessObject.ParentProcessId = m_TypedObject.Field("InheritedFromUniqueProcessId").GetPtr();
    m_ImageBase = m_TypedObject.Field("SectionBaseAddress").GetPtr();
    if ((m_ImageBase == 0ULL) && (m_CcProcessObject.ProcessId == 4))
    {
        //
        // System Process
        //
        m_ImageBase = ExtNtOsInformation::GetNtDebuggerData(DEBUG_DATA_KernBase, "nt", 0);
    }

    m_CcProcessObject.ProcessObjectPtr = m_TypedObject.GetPtr();

    m_TypedObject.Field("ImageFileName").GetString((PTSTR)&m_CcProcessObject.ImageFileName,
        sizeof(m_CcProcessObject.ImageFileName));

    ExtRemoteTypedEx::GetUnicodeString(m_TypedObject.Field("SeAuditProcessCreationInfo.ImageFileName").Field("Name"),
        (PWSTR)&m_CcProcessObject.FullPath,
        sizeof(m_CcProcessObject.FullPath));

    Peb = m_TypedObject.Field("Peb").GetPtr();

    if (Peb)
    {
        ULONG64 ProcessParameters;

        SwitchContext();

        if (IsValid(Peb))
        {
            ProcessParameters = m_TypedObject.Field("Peb").Field("ProcessParameters").GetPtr();

            if (ProcessParameters && IsValid(ProcessParameters))
            {
                ULONG EnvironmentSize;

                m_CcProcessObject.DllPath = ExtRemoteTypedEx::GetUnicodeString2(m_TypedObject.Field("Peb").Field("ProcessParameters").Field("DllPath"));
                REF_POINTER(m_CcProcessObject.DllPath);

                m_CcProcessObject.ImagePathName = ExtRemoteTypedEx::GetUnicodeString2(m_TypedObject.Field("Peb").Field("ProcessParameters").Field("ImagePathName"));
                REF_POINTER(m_CcProcessObject.ImagePathName);

                m_CcProcessObject.CommandLine = ExtRemoteTypedEx::GetUnicodeString2(m_TypedObject.Field("Peb").Field("ProcessParameters").Field("CommandLine"));
                REF_POINTER(m_CcProcessObject.CommandLine);

                ULONG64 Environment = m_TypedObject.Field("Peb").Field("ProcessParameters").Field("Environment").GetPtr();
                if (m_TypedObject.Field("Peb").Field("ProcessParameters").HasField("EnvironmentSize"))
                {
                    EnvironmentSize = (ULONG)m_TypedObject.Field("Peb").Field("ProcessParameters").Field("EnvironmentSize").GetPtr();
                }
                else
                {
                    EnvironmentSize = 0x1000;
                }

                m_EnvVarsBuffer = (LPWSTR)calloc(EnvironmentSize, sizeof(BYTE));
                REF_POINTER(m_EnvVarsBuffer);

                if (g_Ext->m_Data->ReadVirtual(Environment, m_EnvVarsBuffer, EnvironmentSize, NULL) == S_OK)
                {
                    for (UINT Index = 0; Index < (EnvironmentSize / sizeof(WCHAR)); Index += 1)
                    {
                        ENV_VAR_OBJECT EnvVar = {0};

                        if (m_EnvVarsBuffer[Index] == L'\0') continue;

                        ULONG Len = (ULONG)wcslen(&m_EnvVarsBuffer[Index]);

                        EnvVar.Variable = &m_EnvVarsBuffer[Index];
                        m_EnvVars.push_back(EnvVar);
                        Index += Len;
                    }
                }
            }
        }

        RestoreContext();
    }
}

MsDllObject::MsDllObject(
    const MsDllObject& other
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
    *this = other;

    REF_POINTER(m_Image.Image);
}


MsDllObject::~MsDllObject(
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
    Clear();
}

MsProcessObject::MsProcessObject(const MsProcessObject& other)
{
    REF_POINTER(other.m_CcProcessObject.CommandLine);
    REF_POINTER(other.m_CcProcessObject.DllPath);
    REF_POINTER(other.m_CcProcessObject.ImagePathName);

    REF_POINTER(other.m_Image.Image);

    REF_POINTER(other.m_EnvVarsBuffer);

    *this = other;
}

VOID
MsProcessObject::Release(
) throw(...)
/*++

Routine Description:

Description.

Arguments:

-

Return Value:

None.

--*/
{
    DEREF_POINTER(m_CcProcessObject.CommandLine);
    DEREF_POINTER(m_CcProcessObject.DllPath);
    DEREF_POINTER(m_CcProcessObject.ImagePathName);
    DEREF_POINTER(m_EnvVarsBuffer);
}

MsProcessObject::~MsProcessObject(
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
    try
    {
        Release();
    }
    catch (...)
    {

    }

    Clear();
}

VOID
MsPEImageFile::Free(
    VOID
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
    if (m_Image.Initialized)
    {
        DEREF_POINTER(m_Image.Image);
    }

    RtlZeroMemory(&m_Image, sizeof(m_Image));
}

ProcessArray GetProcesses(
    _In_opt_ ULONG64 Pid,
    _In_ ULONG Flags
)
/*++

Routine Description:

    Description.

Arguments:

     Pid - 
     Flags - 

Return Value:

    None.

--*/
{
    ProcessArray ProcessList;
    ProcessArray MmProcessList;

    ProcessIterator Processes;

    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Entering...\n", __FILE__, __FUNCTIONW__, __LINE__);

    for (Processes.First(); !Processes.IsDone(); Processes.Next())
    {
        MsProcessObject ProcObject = Processes.Current();

        if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Current process %s\n", __FILE__, __FUNCTIONW__, __LINE__, ProcObject.m_CcProcessObject.ImageFileName);

        if (!Pid || (Pid == ProcObject.m_CcProcessObject.ProcessId))
        {
            ProcessList.push_back(ProcObject);
        }
    }

    if (!Pid)
    {
        ProcessIterator MmProcesses(ProcessLinksMmType);

        for (MmProcesses.First(); !MmProcesses.IsDone(); MmProcesses.Next())
        {
            MsProcessObject ProcObject = MmProcesses.Current();

            MmProcessList.push_back(MmProcesses.Current());
        }

        //
        // Note: MmProcessList doesn't contain System process (PID = 4).
        // Retrieve hidden process.
        //
        for each (MsProcessObject MmProcObject in MmProcessList)
        {
            BOOLEAN Found = FALSE;

            for each (MsProcessObject ProcObject in ProcessList)
            {
                if (MmProcObject.m_CcProcessObject.ProcessId == ProcObject.m_CcProcessObject.ProcessId) Found = TRUE;
            }

            if (Found == FALSE)
            {
                //
                // MmObject can't be founded. It means it had been removed from the ActiveProcess linked-list (DKOM Attack).
                //
                MmProcObject.m_CcProcessObject.HiddenProcess = TRUE;

                ProcessList.push_back(MmProcObject);
            }
        }
    }


    //
    // Security Tokens, Protected, BreakOnTermination
    //

    //
    // We initialize the structure (allocate buffer etc.), once we don't need any further push_back() in the vector.
    // to avoid memory leaks etc. Because of the destructor.
    //
    //
    // Process + Dlls
    //
    for (ULONG i = 0; i < ProcessList.size(); i++)
    {
        BOOLEAN Initialized = FALSE;
        MsProcessObject& ProcObj = ProcessList[i];

        ProcObj.SwitchContext();

        Initialized = ProcObj.GetInfoFull();

        if (Flags & PROCESS_DLLS_FLAG) {
            if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Get DLL list for %s (Pid=0x%llx)\n", __FILE__, __FUNCTIONW__, __LINE__, ProcObj.m_CcProcessObject.ImageFileName, ProcObj.m_CcProcessObject.ProcessId);
            ProcObj.GetDlls();
        }

        if (Initialized && (Flags & PROCESS_EXPORTS_FLAG)) ProcObj.RtlGetExports();

        if (Flags & PROCESS_DLLS_FLAG)
        {
            for (ULONG j = 0; j < ProcObj.m_DllList.size(); j++)
            {
                MsDllObject& DllObj = ProcObj.m_DllList[j];

                if (Flags & PROCESS_DLL_EXPORTS_FLAG)
                {
                    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Get DLL information for %s!%S\n", __FILE__, __FUNCTIONW__, __LINE__, ProcObj.m_CcProcessObject.ImageFileName, DllObj.mm_CcDllObject.DllName);
                    DllObj.GetInfoFull();

                    DllObj.RtlGetExports();

                    DllObj.Free();
                }
            }
        }

        ProcObj.Free();

        ProcObj.RestoreContext();
    }

    //
    // Strings
    //
    return ProcessList;
}

MsProcessObject
FindProcessByName(
    _In_ LPSTR ProcessName
)
/*++

Routine Description:

    Description.

Arguments:

     ProcessName -

Return Value:

    None.

--*/
{
    ProcessIterator Processes;
    MsProcessObject ProcObject;

    for (Processes.First(); !Processes.IsDone(); Processes.Next())
    {
        ProcObject = Processes.Current();

        if (_stricmp(ProcObject.m_CcProcessObject.ImageFileName, ProcessName) == 0)
        {
            BOOLEAN Result;

            //
            // Save, and change the current process.
            //
            ProcObject.SwitchContext();

            Result = ProcObject.GetInfoFull();
            // ASSERT(Result);

            ProcObject.RestoreContext();

            break;
        }
    }

    return ProcObject;
}

MsProcessObject
FindProcessByPid(
    _In_ ULONG64 ProcessId
)
/*++

Routine Description:

    Description.

Arguments:

     ProcessId - 

Return Value:

    None.

--*/
{
    ProcessIterator Processes;
    MsProcessObject ProcObject;

    MsProcessObject Result;

    for (Processes.First(); !Processes.IsDone(); Processes.Next())
    {
        ProcObject = Processes.Current();

        if (ProcObject.m_CcProcessObject.ProcessId == ProcessId)
        {
            Result = Processes.Current();
            /*
            BOOLEAN Result;

            ProcObject.SwitchContext();

            Result = ProcObject.GetInfoFull();
            // ASSERT(Result);

            ProcObject.RestoreContext();
            */

            break;
        }
    }

    return Result;
}

BOOLEAN
MsProcessObject::MmGetFirstVad(
    _Inout_ PVAD_OBJECT VadInfo
)
{
    ULONG64 First, LeftChild = 0;
    ExtRemoteTyped MmVad;

    if (m_TypedObject.Field("VadRoot").GetTypeSize() > GetPtrSize())
    {
        First = m_TypedObject.Field("VadRoot.BalancedRoot.RightChild").GetPtr();
        if (g_Verbose) g_Ext->Dml("[%s!%S!%d] VadRoot.BalancedRoot.RightChild = 0x%llx\n", __FILE__, __FUNCTIONW__, __LINE__, First);
        if (!First) return FALSE;
    }
    else
    {
        if (m_TypedObject.Field("VadRoot").HasField("Root")) {
            First = m_TypedObject.Field("VadRoot").Field("Root").GetPtr();
        } else {
            First = m_TypedObject.Field("VadRoot").GetPtr();
        }
        if (g_Verbose) g_Ext->Dml("[%s!%S!%d] VadRoot = 0x%llx\n", __FILE__, __FUNCTIONW__, __LINE__, First);
        if (!First) return FALSE;
    }

    while (First)
    {
        LeftChild = First;

        MmVad = ExtRemoteTyped("(nt!_MMVAD *)@$extin", LeftChild);

        if (MmVad.HasField("Core")) {

            if (g_Verbose) g_Ext->Dml("[%s!%S!%d] [Left] LeftChild = 0x%llx\n", __FILE__, __FUNCTIONW__, __LINE__, LeftChild);

            if (MmVad.Field("Core").Field("VadNode").HasField("LeftChild")) {

                First = MmVad.Field("Core").Field("VadNode").Field("LeftChild").GetPtr();
            }
            else {

                First = MmVad.Field("Core").Field("VadNode").Field("Left").GetPtr();
            }
        }
        else {

            First = MmVad.Field("LeftChild").GetPtr();
        }

        if (g_Verbose) g_Ext->Dml("[%s!%S!%d] VadRoot.First = 0x%llx\n", __FILE__, __FUNCTIONW__, __LINE__, First);
    }

    First = LeftChild;
    VadInfo->FirstNode = First;
    VadInfo->CurrentNode = VadInfo->FirstNode;

    MmVad = ExtRemoteTyped("(nt!_MMVAD *)@$extin", VadInfo->CurrentNode);

    if (MmVad.HasField("Core")) {

        VadInfo->StartingVpn = MmVad.Field("Core").Field("StartingVpn").GetUlong();
        VadInfo->EndingVpn = MmVad.Field("Core").Field("EndingVpn").GetUlong();
    }
    else {
        VadInfo->StartingVpn = MmVad.Field("StartingVpn").GetPtr();
        VadInfo->EndingVpn = MmVad.Field("EndingVpn").GetPtr();
    }
    VadInfo->EndingVpn += 1;

    return TRUE;
}

BOOLEAN
MsProcessObject::MmGetNextVad(
    _Inout_ PVAD_OBJECT VadInfo
)
/*++

Routine Description:

    Description.

Arguments:

     VadInfo - 

Return Value:

    BOOLEAN.

--*/
{
    ULONG64 Parent, Next;
    ULONG64 LeftChild = 0, RightChild;

    ExtRemoteTyped MmVad;

     if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Entering...\n", __FILE__, __FUNCTIONW__, __LINE__);

    VadInfo->StartingVpn = 0;
    VadInfo->EndingVpn = 0;
    VadInfo->FileObject = 0;
    if (!VadInfo->CurrentNode) {
        if (g_Verbose) g_Ext->Dml("[%s!%S!%d] CurrentNode is null. Exiting.\n", __FILE__, __FUNCTIONW__, __LINE__);
        return FALSE;
    }

    Next = VadInfo->CurrentNode;

    MmVad = ExtRemoteTyped("(nt!_MMVAD *)@$extin", VadInfo->CurrentNode);

    if (MmVad.HasField("Core")) {

        if (MmVad.Field("Core").Field("VadNode").HasField("RightChild")) {

            RightChild = MmVad.Field("Core").Field("VadNode").Field("RightChild").GetPtr();
        }
        else {

            RightChild = MmVad.Field("Core").Field("VadNode").Field("Right").GetPtr();
        }
    }
    else {

        RightChild = MmVad.Field("RightChild").GetPtr();
    }

    if (!RightChild)
    {
        if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Looking for parent node.\n", __FILE__, __FUNCTIONW__, __LINE__);
        while (TRUE)
        {
            if (MmVad.HasField("u1.Parent"))
            {
                Parent = MmVad.Field("u1.Parent").GetPtr();
            }
            else if (MmVad.HasField("Parent"))
            {
                Parent = MmVad.Field("Parent").GetPtr();
            }
            else if (MmVad.HasField("Core.VadNode.u1.Parent")) {

                Parent = MmVad.Field("Core").Field("VadNode.u1.Parent").GetPtr();
            }
            else if (MmVad.HasField("Core.VadNode.ParentValue")) {

                Parent = MmVad.Field("Core").Field("VadNode.ParentValue").GetPtr();
            }
            else return FALSE;

            //
            // Sanitize
            //
            Parent &= ~0x3;
            if (!Parent) return FALSE;

            if (Parent == Next)
            {
                VadInfo->CurrentNode = 0;
                return FALSE;
            }

            if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Trying to access VadInfo->CurrentNode = 0x%llx\n",
                __FILE__, __FUNCTIONW__, __LINE__, VadInfo->CurrentNode);

            MmVad = ExtRemoteTyped("(nt!_MMVAD *)@$extin", Parent);

            if (MmVad.HasField("Core")) {

                if (MmVad.Field("Core").Field("VadNode").HasField("LeftChild")) {

                    LeftChild = MmVad.Field("Core").Field("VadNode").Field("LeftChild").GetPtr();
                }
                else {

                    LeftChild = MmVad.Field("Core").Field("VadNode").Field("Left").GetPtr();
                }
            }
            else {

                LeftChild = MmVad.Field("LeftChild").GetPtr();
            }

            if (LeftChild == Next)
            {
                VadInfo->CurrentNode = Parent;
                break;
            }

            Next = Parent;
        }
    }
    else
    {
        Next = RightChild;

        while (Next)
        {
            LeftChild = Next;
            if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Trying to access [0x%llX] Node\n",
                __FILE__, __FUNCTIONW__, __LINE__, LeftChild);

            if (!IsValid(LeftChild)) {
                g_Ext->Err("[%s!%S!%d] Unable to get LeftChild of nt!_MMVAD_SHORT at 0x%llX\n", __FILE__, __FUNCTIONW__, __LINE__, LeftChild);
                return FALSE;
            }

            MmVad = ExtRemoteTyped("(nt!_MMVAD *)@$extin", LeftChild);

            if (MmVad.HasField("Core")) {

                if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Trying to access [0x%llX].Core.VadNode.Left\n", __FILE__, __FUNCTIONW__, __LINE__, LeftChild);

                if (MmVad.Field("Core").Field("VadNode").HasField("LeftChild")) {

                    Next = MmVad.Field("Core").Field("VadNode").Field("LeftChild").GetPtr();
                }
                else {

                    Next = MmVad.Field("Core").Field("VadNode").Field("Left").GetPtr();
                }
            }
            else {

                Next = MmVad.Field("LeftChild").GetPtr();
            }
        }

        VadInfo->CurrentNode = LeftChild;

        if (!LeftChild) return FALSE;
    }

    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Current Node [0x%llX]\n", __FILE__, __FUNCTIONW__, __LINE__, VadInfo->CurrentNode);

    MmVad = ExtRemoteTyped("(nt!_MMVAD *)@$extin", VadInfo->CurrentNode);

    if (MmVad.HasField("Core")) {

        VadInfo->StartingVpn = MmVad.Field("Core").Field("StartingVpn").GetUlong();
        VadInfo->EndingVpn = MmVad.Field("Core").Field("EndingVpn").GetUlong();

        VadInfo->VadType = (ULONG)MmVad.Field("Core").Field("u.VadFlags.VadType").GetUlong();
        VadInfo->Protection = (ULONG)MmVad.Field("Core").Field("u.VadFlags.Protection").GetUlong();
        VadInfo->PrivateMemory = (ULONG)MmVad.Field("Core").Field("u.VadFlags.PrivateMemory").GetUlong();
        VadInfo->MemCommit = (ULONG)MmVad.Field("Core").Field("u1.VadFlags1.MemCommit").GetUlong();

        if (MmVad.HasField("Core.StartingVpnHigh") && MmVad.HasField("Core.EndingVpnHigh")) {

            ULONG64 StartingVpnHigh;
            ULONG64 EndingVpnHigh;

            StartingVpnHigh = MmVad.Field("Core").Field("StartingVpnHigh").GetUchar();
            EndingVpnHigh = MmVad.Field("Core").Field("EndingVpnHigh").GetUchar();

            VadInfo->StartingVpn = VadInfo->StartingVpn | (StartingVpnHigh << 32);
            VadInfo->EndingVpn = VadInfo->EndingVpn | (EndingVpnHigh << 32);
        }
    }
    else {
        VadInfo->StartingVpn = MmVad.Field("StartingVpn").GetPtr();
        VadInfo->EndingVpn = MmVad.Field("EndingVpn").GetPtr();

        if (MmVad.HasField("u.VadFlags.VadType"))
        {
            VadInfo->VadType = (ULONG)MmVad.Field("u.VadFlags.VadType").GetPtr();
        }
        VadInfo->Protection = (ULONG)MmVad.Field("u.VadFlags.Protection").GetPtr();
        VadInfo->PrivateMemory = (ULONG)MmVad.Field("u.VadFlags.PrivateMemory").GetPtr();
        VadInfo->MemCommit = (ULONG)MmVad.Field("u.VadFlags.MemCommit").GetPtr();
    }
    VadInfo->EndingVpn += 1;

    if (MmVad.HasField("ControlArea"))
    {
        // NT 5
        ULONG64 ControlArea = 0;
        ULONG64 FilePointer = 0;

        ControlArea = MmVad.Field("ControlArea").GetPtr();
        if (ControlArea && IsValid(ControlArea)) FilePointer = MmVad.Field("ControlArea").Field("FilePointer").GetPtr();

        VadInfo->FileObject = FilePointer;
    }
    else if (MmVad.HasField("Subsection"))
    {
        ULONG64 Subsection = MmVad.Field("Subsection").GetPtr();
        if (Subsection && !VadInfo->PrivateMemory)
        {
            ExtRemoteTyped MmSubSection("(nt!_SUBSECTION *)@$extin", Subsection);

            if (MmSubSection.Field("ControlArea").GetPtr())
            {
                VadInfo->FileObject = MmSubSection.Field("ControlArea").Field("FilePointer").Field("Object").GetPtr();
            }
        }
    }

    if (GetPtrSize() == sizeof(ULONG64))  VadInfo->FileObject &= ~0xF;
    else if (GetPtrSize() == sizeof(ULONG32)) VadInfo->FileObject &= ~0x7;

    if (g_Verbose) g_Ext->Dml("[%s!%S!%d] Leaving.\n", __FILE__, __FUNCTIONW__, __LINE__);

    return TRUE;
}

BOOLEAN
MsProcessObject::MmGetVads(
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
    VAD_OBJECT VadInfo = { 0 };

    BOOLEAN Result;

    Result = MmGetFirstVad(&VadInfo);
    while (Result)
    {
        m_Vads.push_back(VadInfo);
        Result = MmGetNextVad(&VadInfo);
    }

    return TRUE;
}

BOOLEAN
MsProcessObject::GetThreads(
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
    ULONG64 ThreadListHead = m_TypedObject.Field("ThreadListHead").GetPointerTo().GetPtr();

    ExtRemoteTypedList ThreadList(ThreadListHead, "nt!_ETHREAD", "ThreadListEntry");

    for (ThreadList.StartHead(); ThreadList.HasNode(); ThreadList.Next())
    {
        THREAD_OBJECT ThreadObject = { 0 };

        ThreadObject.CrossThreadFlags = ThreadList.GetTypedNode().Field("CrossThreadFlags").GetUlong();
        if (ThreadList.GetTypedNode().HasField("Tcb.ThreadFlags"))
        {
            ThreadObject.ThreadFlags = ThreadList.GetTypedNode().Field("Tcb.ThreadFlags").GetUlong();
        }

        ThreadObject.StartAddress = ThreadList.GetTypedNode().Field("StartAddress").GetPtr();
        ThreadObject.Win32StartAddress = ThreadList.GetTypedNode().Field("Win32StartAddress").GetPtr();

        if (!ThreadObject.Win32StartAddress) {

            ThreadObject.Win32StartAddress = ThreadObject.StartAddress;
        }

        ThreadObject.ProcessId = ThreadList.GetTypedNode().Field("Cid.UniqueProcess").GetPtr();
        ThreadObject.ThreadId = ThreadList.GetTypedNode().Field("Cid.UniqueThread").GetPtr();

        ThreadObject.CreateTime.QuadPart = ThreadList.GetTypedNode().Field("CreateTime.QuadPart").GetUlong64();
        ThreadObject.ExitTime.QuadPart = ThreadList.GetTypedNode().Field("ExitTime.QuadPart").GetUlong64();

        if (ThreadList.GetTypedNode().HasField("Tcb.ServiceTable"))
        {
            ThreadObject.ServiceTable = ThreadList.GetTypedNode().Field("Tcb.ServiceTable").GetPtr();
        }

        m_Threads.push_back(ThreadObject);
    }

    return TRUE;
}