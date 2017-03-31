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

    - System.h

Abstract:

    - 

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/


#ifndef __SYSTEM_H__
#define __SYSTEM_H__

typedef struct _SSDT_ENTRY {
    ULONG Index;
    MsPEImageFile::ADDRESS_INFO Address;
    BOOLEAN InlineHooking;
    BOOLEAN PatchedEntry;
} SSDT_ENTRY, *PSSDT_ENTRY;

#define SC_SIGNATURE_NT6           0x48726373 // "scrH" in ASCII.
#define HANDLE_SIGNATURE           0x48726573 // "serH" in ASCII.

#define SC_SIGNATURE_NT5           0x6E4F6373  // "scOn" in ASCII.
#define SERVICE_SIGNATURE          0x76724573  // "sErv" in ASCII.

#define INTERRUPT_OBJECT_TYPE      22

#define IDT_ACCESS_TYPE_MASK       0x0F00
#define IDT_ACCESS_DPL_MASK        0x6000
#define IDT_ACCESS_PRESENT_MASK    0x8000

typedef struct _SERVICE_ENTRY {
    WCHAR Name[MAX_PATH];
    WCHAR Desc[MAX_PATH];
    WCHAR CommandLine[MAX_PATH];
    WCHAR AccountName[MAX_PATH];

    ULONG64 TokenHandle;
    ULONG64 ProcessHandle;
    ULONG ProcessId;

    ULONG ServiceCount; // number of services running in the process
    ULONG UseCount; // how many handles open to service

    SERVICE_STATUS ServiceStatus;
    ULONG StartType;
} SERVICE_ENTRY, *PSERVICE_ENTRY;

typedef struct _PARTITION_ENTRY
{
    UCHAR BootableFlag;
    UCHAR StartingCHS[3];
    UCHAR PartitionType;
    UCHAR EndingCHS[3];
    ULONG StartingLBA;
    ULONG SizeInSectors;
} PARTITION_ENTRY, *PPARTITION_ENTRY;

typedef struct _PARTITION_TABLE
{
    UCHAR u00[0x1b8];
    UCHAR DiskSignature[4]; // Boot code
    USHORT u1bc;
    PARTITION_ENTRY Entry[4];
    ULONG Signature;
} PARTITION_TABLE, *PPARTITION_TABLE;

typedef struct _VACB_OBJECT
{
    ULONG64 Vacb;
    ULONG64 BaseAddress;
    BOOLEAN ValidBase;
    ULONG64 SharedCacheMap;
} VACB_OBJECT, *PVACB_OBJECT;

typedef struct _IDT_ENTRY {
    ULONG CoreIndex;
    ULONG Index;
    ULONG64 Address;

    USHORT Dpl;
    USHORT Present;
    USHORT Type;
} IDT_ENTRY, *PIDT_ENTRY;

typedef struct _IDT_TABLE {
    ULONG64 IdtAddress;
    ULONG64 PrcbAddress;
} IDT_TABLE, *PIDT_TABLE;

typedef struct _GDT_OBJECT
{
    ULONG CoreIndex;
    ULONG Index;

    ULONG Selector;
    ULONG64 Base;
    ULONG64 Limit;
    ULONG Present;
    ULONG Type;
    ULONG Dpl;
    ULONG64 Entry;
} GDT_OBJECT, *PGDT_OBJECT;

typedef enum _KOBJECTS
{
    EventNotificationObject = 0,
    EventSynchronizationObject = 1,
    MutantObject = 2,
    ProcessObject = 3,
    QueueObject = 4,
    SemaphoreObject = 5,
    ThreadObject = 6,
    GateObject = 7,
    TimerNotificationObject = 8,
    TimerSynchronizationObject = 9,
    Spare2Object = 10,
    Spare3Object = 11,
    Spare4Object = 12,
    Spare5Object = 13,
    Spare6Object = 14,
    Spare7Object = 15,
    Spare8Object = 16,
    Spare9Object = 17,
    ApcObject = 18,
    DpcObject = 19,
    DeviceQueueObject = 20,
    EventPairObject = 21,
    InterruptObject = 22,
    ProfileObject = 23,
    ThreadedDpcObject = 24,
    MaximumKernelObject = 25
} KOBJECTS;

typedef struct _KTIMER {
    ULONG CoreId;
    ULONG64 Timer;
    ULONG64 Dpc;
    ULONG Type;
    ULONG DpcType;
    LARGE_INTEGER DueTime;
    ULONG Period;
    ULONG64 DeferredRoutine;
} KTIMER, *PKTIMER;

typedef union _KGDTENTRY64
{
    struct
    {
        USHORT LimitLow;
        USHORT BaseLow;
        union
        {
            struct {
                USHORT BaseHigh;
            };
            struct
            {
                UCHAR BaseMiddle;
                UCHAR Flags1;
                UCHAR Flags2;
                UCHAR BaseHigh;
            } Bytes;
            struct
            {
                ULONG BaseMiddle : 8;
                ULONG Type : 5;
                ULONG Dpl : 2;
                ULONG Present : 1;
                ULONG LimitHigh : 4;
                ULONG System : 1;
                ULONG LongMode : 1;
                ULONG DefaultBig : 1;
                ULONG Granularity : 1;
                ULONG BaseHigh : 8;
            } Bits;
        };
        ULONG BaseUpper;
        ULONG MustBeZero;
    };
    UINT64 Alignment;
} KGDTENTRY64, *PKGDTENTRY64;

typedef struct _CALL_GATE
{
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR NumberOfArguments : 5;
    UCHAR Reserved : 3;
    UCHAR Type : 5;
    UCHAR Dpl : 2;
    UCHAR Present : 1;
    USHORT OffsetHigh;
} CALL_GATE, *PCALL_GATE;

enum GDTSystemType32
{
    TaskStateSegment16Available = 1,
    LocalDescriptorTable32 = 2,
    TaskStateSegment16Busy = 3,
    CallGate16 = 4,
    TaskGate = 5,
    InterruptGate16 = 6,
    TrapGate16 = 7,
    TaskStateSegment32Available = 9,
    TaskStateSegment32Busy = 11,
    CallGate32 = 12,
    InterruptGate32 = 14,
    TrapGate32 = 15,
    Invalid32 = 255
};

enum GDTSystemType64
{
    UpperHalf16 = 0,
    LocalDescriptorTable64 = 2,
    TaskStateSegment64Available = 9,
    TaskStateSegment64Busy = 11,
    CallGate64 = 12,
    InterruptGate64 = 14,
    TrapGate64 = 15,
    Invalid64 = 255
};

enum GDTType
{
    System = 0,
    Data = 1,
    Code = 2
};


typedef enum _WORK_QUEUE_TYPE {
    CriticalWorkQueue,
    DelayedWorkQueue,
    HyperCriticalWorkQueue,
    NormalWorkQueue,
    BackgroundWorkQueue,
    RealTimeWorkQueue,
    SuperCriticalWorkQueue,
    MaximumWorkQueue,
    CustomPriorityWorkQueue = 32
} WORK_QUEUE_TYPE;

vector<VACB_OBJECT>
GetVacbs(
    VOID
    );

vector<KTIMER>
GetTimers(
    VOID
    );

vector<SSDT_ENTRY>
GetServiceDescriptorTable(
    VOID
    );

PSTR
GetServiceStartType(
    _In_ ULONG StartType
    );

PSTR
GetServiceState(
    _In_ ULONG State
    );

vector<SERVICE_ENTRY>
GetServices(
    VOID
    );

PSTR
GetPartitionType(
    _In_ ULONG Type
    );

vector<IDT_ENTRY>
GetInterrupts(
    _In_opt_ ULONG64 InIdtBase
    );

vector<GDT_OBJECT>
GetDescriptors(
    _In_opt_ ULONG64 InGdtBase
    );

void
GetExQueue(
);
#endif