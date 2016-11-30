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

    - Network.h

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include "SwishDbgExt.h"

#ifndef __NETWORK_H__
#define __NETWORK_H__

#define PROTOCOL_AH     51
#define PROTOCOL_ESP    50
#define PROTOCOL_COMP   108
#define PROTOCOL_TCP    6
#define PROTOCOL_UDP    17
#define PROTOCOL_RSVP   46
#define PROTOCOL_ICMP   1

/* Dynamic hash table */
typedef struct _RTL_DYNAMIC_HASH_TABLE {
    ULONG   Flags;
    ULONG   Shift;
    ULONG   TableSize;
    ULONG   Pivot;
    ULONG   DivisorMask;
    ULONG   NumEntries;
    ULONG   NonEmptyBuckets;
    ULONG   NumEnumerators;
    ULONG64   Directory;
} RTL_DYNAMIC_HASH_TABLE, *PRTL_DYNAMIC_HASH_TABLE;

//
// TCP_HASH_TABLES
//
//typedef struct DECLSPEC_CACHEALIGN _TCP_HASH_TABLES {
//    RTL_DYNAMIC_HASH_TABLE TcbTable;
//    RTL_DYNAMIC_HASH_TABLE TimeWaitTcbTable;
//    RTL_DYNAMIC_HASH_TABLE StandbyTcbTable;
//    RTL_DYNAMIC_HASH_TABLE SynTcbTable;
//} TCP_HASH_TABLES, *PTCP_HASH_TABLES;

//
// TCP_PARTITION
//
// Maintains a partition of TCP connection hash-tables.
//

typedef struct _TCP_PARTITION {
    ULONG64 Lock;
    ULONG64 HashTables;
    ULONG64 IpHashTables;
    ULONG64 TimerWheels;
    LIST_ENTRY ReassemblyListHead;
    SINGLE_LIST_ENTRY DelayQueueEntry;
} TCP_PARTITION, *PTCP_PARTITION;

typedef enum {
    TcbClosedState,
    TcbListenState,
    TcbSynSentState,
    TcbSynRcvdState,
    TcbEstablishedState,
    TcbFinWait1State,
    TcbFinWait2State,
    TcbCloseWaitState,
    TcbClosingState,
    TcbLastAckState,
    TcbTimeWaitState,
    TcbMaximumState
} TCB_STATE, *PTCB_STATE;

typedef enum _NETIO_DISPATCH_ID {
    NetIoDispatchIpsec = 0,
    NetIoDispatchKfd = 1,
    NetIoDispatchAle = 2,
    NetIoDispatchEQOS = 3,
    NetIoDispatchIDP = 4,
    NetIoDispatchMax = 5
} NETIO_DISPATCH_ID;

typedef struct _NETWORK_ENTRY {
    ULONG64 ObjectPtr;

    ULONG Protocol;
    ULONG State;
    LARGE_INTEGER CreationTime;

    struct {
        union {
            UCHAR IPv6_Addr[16];
            UCHAR IPv4_Addr[4];
        };
        ULONG Port;
    } Local;

    struct {
        union {
            UCHAR IPv6_Addr[16];
            UCHAR IPv4_Addr[4];
        };
        ULONG Port;
    } Remote;

    union {
        ULONG64 ProcessObject;
        ULONG64 ProcessId;
    };

    CHAR ProcessName[16];
} NETWORK_ENTRY, *PNETWORK_ENTRY;

class Network {
public:
    typedef struct _OBJECT_ENTRY_X86 {
        ULONG32 Next;
        UCHAR Unknow04[0x08];
        UCHAR Unknow0C[0x20];
        UCHAR LocalAddress[4];
        UCHAR Port[2];
        USHORT Protocol;
        UCHAR Unknow34[0x114];
        ULONG ProcessId;
        UCHAR Unknow14C[0xC];
        LARGE_INTEGER CreationTime;
    } OBJECT_ENTRY_X86, *POBJECT_ENTRY_X86;
};

vector<NETWORK_ENTRY>
GetSockets(
);

PSTR
GetProtocolType(
ULONG Type
);

LPSTR
GetTcbState(
    ULONG State
);

#endif