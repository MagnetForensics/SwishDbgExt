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

    - Process.h

Abstract:

    - ExtRemoteData Pointer(GetExpression("'htsxxxxx!gRingBuffer"), m_PtrSize); // <<< works just fine

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef __PROCESS_H__
#define __PROCESS_H__

#define DEREF_POINTER(Ptr) { \
if (Ptr && (g_References[Ptr] >= 1)) \
    { \
        g_References[Ptr] -= 1; \
        /* g_Ext->Dml("(%s:%d::%s) [%d] ", __FILE__, __LINE__, __FUNCTION__, g_References[Ptr]); */ \
        if (g_References[Ptr] == 0) \
        {\
            /* g_Ext->Dml("free(Ptr) = %p", Ptr); */ \
            free(Ptr); \
        } \
        Ptr = NULL; \
        /* g_Ext->Dml("\n"); */\
    } \
}

#define REF_POINTER(Ptr) { \
if (Ptr) \
    { \
        if (g_References.find(Ptr) == g_References.end()) \
        { \
            g_References.insert(pair<PVOID, ULONG>(Ptr, 1)); \
        } \
        else \
        { \
            g_References[Ptr] += 1; \
        } \
        /* g_Ext->Dml("(%s:%d::%s) [%d] Ref(%p) \n", __FILE__, __LINE__, __FUNCTION__, g_References[Ptr], Ptr); */ \
    } \
}

#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define PROCESS_DLLS_FLAG (1 << 0)
#define PROCESS_EXPORTS_FLAG (1 << 1)
#define PROCESS_DLL_EXPORTS_FLAG (1 << 2)
#define PROCESS_SCAN_MALICIOUS_FLAG (1 << 3)
#define PROCESS_HANDLES_FLAG (1 << 4)
#define PROCESS_VADS_FLAG (1 << 5)
#define PROCESS_THREADS_FLAG (1 << 6)
#define PROCESS_ENVVAR_FLAG (1 << 7)

#define OBP_CREATOR_INFO_BIT 0x1
#define OBP_NAME_INFO_BIT 0x2
#define OBP_HANDLE_INFO_BIT 0x4
#define OBP_QUOTA_INFO_BIT 0x8
#define OBP_PROCESS_INFO_BIT 0x10

typedef struct _THREAD_OBJECT {
    ULONG64 StartAddress;
    ULONG64 ServiceTable;

    ULONG ThreadFlags;
    ULONG CrossThreadFlags;
    ULONG64 OwningProcess;
    ULONG64 AttachedProcess;

    ULONG64 ProcessId;
    ULONG64 ThreadId;

    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;

    ULONG64 Win32StartAddress;
} THREAD_OBJECT, *PTHREAD_OBJECT;

typedef struct _HANDLE_OBJECT {
    ULONG Handle;
    WCHAR Name[MAX_PATH + 1];
    WCHAR Type[32];
    ULONG ObjectTypeIndex;
    ULONG64 ObjectPtr;
    ULONG64 ObjectKcb; // Only for Keys
} HANDLE_OBJECT, *PHANDLE_OBJECT;

typedef struct _VAD_OBJECT {
    ULONG64 ProcessObject;
    ULONG64 FirstNode;
    ULONG64 CurrentNode;
    ULONG64 StartingVpn;
    ULONG64 EndingVpn;

    ULONG32 VadType;
    ULONG32 Protection;
    ULONG32 PrivateMemory;
    ULONG32 MemCommit;

    ULONG64 FileObject;
} VAD_OBJECT, *PVAD_OBJECT;

class ModuleIterator {
public:
    ModuleIterator(ULONG64 ModuleHead);
    BOOLEAN IsDone(VOID);
    VOID First(VOID);
    ExtRemoteTyped Current(VOID);
    // ExtRemoteTyped CurrentNode(VOID);
    VOID Next(VOID);
    VOID Prev(VOID);

private:
    ULONG64 m_ModuleListHead;
    ExtRemoteTypedList m_ModuleList;
};

typedef enum _PROCESS_LINKS_TYPE {
    ProcessLinksDefaultType = 0,
    ProcessLinksMmType = 1
} PROCESS_LINKS_TYPE;

class ProcessIterator {
public:
    ProcessIterator(PROCESS_LINKS_TYPE Type = ProcessLinksDefaultType);
    BOOLEAN IsDone(VOID);
    VOID First(VOID);
    ExtRemoteTyped Current(VOID);
    ExtRemoteTyped CurrentNode(VOID);
    VOID Next(VOID);
    VOID Prev(VOID);

private:
    PROCESS_LINKS_TYPE m_LinksType;
    ULONG64 m_ProcessHead;
    ExtRemoteTypedList m_ProcessList;
};

class MsDllObject : public MsPEImageFile {
public:
    typedef struct DLL_INFO {
        IMAGE_TYPE ImageType; // Always in first position.

        BOOLEAN IsWow64;

        ULONG64 ProcessOwner;
        ULONG64 DirectoryTableBase;
        ULONG64 DllEntry;

        ULONG64 LoadTime;
        WCHAR DllName[MAX_PATH + 1];
        WCHAR FullDllName[MAX_PATH + 1];
    } DLL_INFO, *PDLL_INFO;

    MsDllObject()
    {
        Clear();
    }

    MsDllObject(ExtRemoteTyped Object)
    {
        Clear();
        m_TypedObject = Object;
        Set();
    }
    ~MsDllObject();

    MsDllObject::MsDllObject(const MsDllObject& other);

    VOID Set();

    BOOLEAN Init(VOID);

    DLL_INFO mm_CcDllObject;

    ExtRemoteTyped m_TypedObject;
};

class MsProcessObject : public MsPEImageFile {
public:
    typedef struct _ENV_VAR_OBJECT {
        LPWSTR Variable;
    } ENV_VAR_OBJECT, *PENV_VAR_OBJECT;

    typedef struct _CACHED_PROCESS_OBJECT {
        IMAGE_TYPE ImageType; // Always in first position.

        ULONG64 ProcessObjectPtr;

        ULONG64 CreateTime;
        ULONG64 ExitTime;

        ULONG64 ParentProcessId;
        ULONG64 ProcessId;

        ULONG64 VirtualSize;

        //
        // Additional information
        //
        BOOLEAN HiddenProcess;

        ULONG32 ProtectedProcess;
        ULONG32 BreakOnTermination;

        CHAR ImageFileName[16];
        WCHAR FullPath[MAX_PATH + 1];

        LPWSTR CommandLine;
        WCHAR WindowTitle[256];
        LPWSTR DllPath;
        LPWSTR ImagePathName;
    } CACHED_PROCESS_OBJECT, *PCACHED_PROCESS_OBJECT;

    MsProcessObject()
    {
        Clear();
    }

    /*
    MsProcessObject(MsProcessObject &other)
    {
        m_DllList = other.m_DllList;
        m_CcProcessObject = other.m_CcProcessObject;
        m_Image = other.m_Image;
        m_ProcessDataOffset = other.m_ProcessDataOffset;
        m_TypedObject = other.m_TypedObject;
    }*/
    MsProcessObject(const MsProcessObject& other); // copy constructor

    MsProcessObject(ExtRemoteTyped Object)
    {
        Clear();
        m_EnvVarsBuffer = NULL;
        m_TypedObject = Object;
        Set();
    }
    ~MsProcessObject();

    VOID Set();
    VOID Release() throw(...);

    BOOLEAN GetDlls();
    BOOLEAN GetHandles(ULONG64 InTableCode);

    BOOLEAN SwitchContext(VOID);
    BOOLEAN RestoreContext(VOID);

    BOOLEAN MmGetFirstVad(
        PVAD_OBJECT VadInfo
    );
    BOOLEAN MmGetNextVad(
        PVAD_OBJECT VadInfo
    );
    BOOLEAN MmGetVads();
    BOOLEAN GetThreads();

    CACHED_PROCESS_OBJECT m_CcProcessObject;

    vector<ENV_VAR_OBJECT> m_EnvVars;

    vector<MsDllObject> m_DllList;
    vector<HANDLE_OBJECT> m_Handles;
    vector<VAD_OBJECT> m_Vads;
    vector<THREAD_OBJECT> m_Threads;

    ULONG64 m_ProcessDataOffset;

    ExtRemoteTyped m_TypedObject;
    LPWSTR m_EnvVarsBuffer;
};

typedef vector<MsProcessObject> ProcessArray;

ProcessArray GetProcesses(ULONG64 Pid, ULONG Flags);

MsProcessObject FindProcessByName(LPSTR ProcessName);
MsProcessObject FindProcessByPid(ULONG64 ProcessId);

extern map<PVOID, ULONG> g_References;

#endif