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

    - Network.cpp

    - SMB 

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

//
// TCPIP
// SMB
// NETBIOS
//

#include "MoonSolsDbgExt.h"

PSTR
GetProtocolType(
    ULONG Type
)
{
    switch (Type)
    {
    case PROTOCOL_AH:
        return "AH";
            break;
        case PROTOCOL_ESP:
            return "ESP";
            break;
        case PROTOCOL_COMP:
            return "COMP";
            break;
        case PROTOCOL_TCP:
            return "TCP";
            break;
        case PROTOCOL_UDP:
            return "UDP";
            break;
        case PROTOCOL_RSVP:
            return "RSVP";
            break;
        case PROTOCOL_ICMP:
            return "ICMP";
            break;
    }

    return "UKNWN";
}

LPSTR
GetTcbState(
    ULONG State
)
{
    LPSTR TcbState[] = {
        "CLOSED",
        "LISTEN",
        "SYN SENT",
        "SYN RCVD",
        "ESTABLISHED",
        "FIN WAIT1",
        "FIN WAIT2",
        "CLOSE WAIT",
        "CLOSING",
        "LACK ACK",
        "TIME WAIT",
        NULL
    };

    if (State >= TcbMaximumState) return "UN";

    return TcbState[State];
}

vector<NETWORK_ENTRY>
GetSockets()
{
    ULONG64 TableAddr;
    ULONG64 TableCountAddr;

    PULONG64 Table = NULL;
    ULONG TableCount;

    vector<NETWORK_ENTRY> NetworkEntries;

    ULONG ProcessorType;
    ULONG PlateformId, Major, Minor, ServicePackNumber;

    if (g_Ext->m_Control->GetActualProcessorType(&ProcessorType) != S_OK) goto CleanUp;
    if (g_Ext->m_Control->GetSystemVersion(&PlateformId, &Major, &Minor, NULL, NULL, NULL, &ServicePackNumber, NULL, NULL, NULL) != S_OK) goto CleanUp;

    // g_Ext->Dml("Major: %d, Minor: %d, ProcessorType = %x\n", Major, Minor, ProcessorType);

    if ((Minor < 6000) && (ProcessorType == IMAGE_FILE_MACHINE_I386))
    {
        if (g_Ext->m_Symbols->GetOffsetByName("tcpip!AddrObjTable", &TableAddr) != S_OK) goto CleanUp;
        if (g_Ext->m_Symbols->GetOffsetByName("tcpip!AddrObjTableSize", &TableCountAddr) != S_OK) goto CleanUp;

        if (ReadPointersVirtual(1, TableAddr, &TableAddr) != S_OK) goto CleanUp;
        if (g_Ext->m_Data->ReadVirtual(TableCountAddr, &TableCount, sizeof(ULONG), NULL) != S_OK) goto CleanUp;

        Table = (PULONG64)malloc(TableCount * sizeof(ULONG64));
        if (ReadPointersVirtual(TableCount, TableAddr, Table) != S_OK) goto CleanUp;

        for (UINT i = 0; i < TableCount; i += 1)
        {
            Network::OBJECT_ENTRY_X86 ObjectEntry = { 0 };

            NETWORK_ENTRY NetworkEntry = { 0 };

            if (Table[i] == 0) continue;

            if (g_Ext->m_Data->ReadVirtual(Table[i], &ObjectEntry, sizeof(Network::OBJECT_ENTRY_X86), NULL) != S_OK) goto CleanUp;

            NetworkEntry.ObjectPtr = Table[i];
            NetworkEntry.CreationTime = ObjectEntry.CreationTime;

            NetworkEntry.ProcessId = ObjectEntry.ProcessId;
            NetworkEntry.Protocol = ObjectEntry.Protocol;

            NetworkEntry.Local.Port = (ObjectEntry.Port[1] << 8) | ObjectEntry.Port[0];
            NetworkEntry.Local.IPv4_Addr[3] = ObjectEntry.LocalAddress[3];
            NetworkEntry.Local.IPv4_Addr[2] = ObjectEntry.LocalAddress[2];
            NetworkEntry.Local.IPv4_Addr[1] = ObjectEntry.LocalAddress[1];
            NetworkEntry.Local.IPv4_Addr[0] = ObjectEntry.LocalAddress[0];

            NetworkEntry.State = TcbListenState;

            NetworkEntries.push_back(NetworkEntry);
        }
    }
    else if (Minor > 6000)
    {
        if (g_Ext->m_Symbols->GetOffsetByName("tcpip!PartitionCount", &TableCountAddr) != S_OK) goto CleanUp;

        ReadPointer(GetExpression("tcpip!PartitionTable"), &TableAddr);
        if (!TableAddr) goto CleanUp;
        if (g_Ext->m_Data->ReadVirtual(TableCountAddr, &TableCount, sizeof(ULONG), NULL) != S_OK) goto CleanUp;

        ULONG ListEntrySize = GetTypeSize("nt!_LIST_ENTRY");
        ULONG PoolHeaderSize = GetTypeSize("nt!_POOL_HEADER");

        ExtRemoteUnTyped PartitionTable(TableAddr, "tcpip!_PARTITION_TABLE");

        for (UINT PartitionIndex = 0; PartitionIndex < TableCount; PartitionIndex += 1)
        {
            NETWORK_ENTRY NetworkEntry = { 0 };

            // g_Ext->Dml("    -> Partition[%d].HashTables = 0x%I64X\n", PartitionIndex, Partition->HashTables);
            ExtRemoteTyped HashTable("(nt!_RTL_DYNAMIC_HASH_TABLE *)@$extin", PartitionTable.ArrayElement(PartitionIndex).Field("HashTables").GetPtr());

            ULONG64 Directory = HashTable.Field("Directory").GetPtr();
            ULONG TableEntries = HashTable.Field("TableSize").GetUlong();

            for (UINT i = 0; i < TableEntries; i += 1)
            {
                ExtRemoteTypedList List(Directory + i * ListEntrySize, "nt!_LIST_ENTRY", "Flink");

                for (List.StartHead(); List.HasNode(); List.Next())
                {
                    ULONG64 Current = List.GetNodeOffset();
                    if (!IsValid(Current)) break;

                    ExtRemoteUnTyped Tcb(Current, "tcpip!_TCB");
                    Tcb.SubtractOffset("HashTableEntry");

                    ExtRemoteTyped PoolHeader("(nt!_POOL_HEADER *)@$extin", Tcb.GetPointerTo() - PoolHeaderSize);
                    if (PoolHeader.Field("PoolTag").GetUlong() != 'EpcT') continue;

                    //# Seen as 0x1f0 on Vista SP0, 0x1f8 on Vista SP2 and 0x210 on 7
                    //# Seen as 0x320 on Win7 SP0 x64
                    ULONG PoolSize;
                    if (PoolHeader.Field("BlockSize").GetTypeSize() == sizeof(USHORT))
                    {
                        PoolSize = PoolHeader.Field("BlockSize").GetUshort() * 0x10;
                    }
                    else
                    {
                        PoolSize = PoolHeader.Field("BlockSize").GetUlong() * 0x10;
                    }

                    if (PoolSize < 0x100) continue;

                    ULONG64 SrcAddress = 0;
                    ULONG64 DstAddress = 0;

                    NetworkEntry.Protocol = PROTOCOL_TCP;
                    NetworkEntry.State = Tcb.Field("State").GetUlong();
                    NetworkEntry.Local.Port = Tcb.Field("LocalPort").GetUshort();
                    NetworkEntry.Remote.Port = Tcb.Field("RemotePort").GetUshort();

                    DstAddress = Tcb.Field("Path", TRUE).Field("DestinationAddress").GetPtr();
                    if (IsValid(Tcb.Field("Path").GetPtr() &&
                        IsValid(Tcb.Field("Path", TRUE).Field("SourceAddress").GetPtr()) &&
                        IsValid(Tcb.Field("Path", TRUE).Field("SourceAddress", TRUE).Field("Identifier").GetPtr()) &&
                        IsValid(Tcb.Field("Path", TRUE).Field("SourceAddress", TRUE).Field("Identifier", TRUE).Field("Address").GetPtr())))
                    {
                        SrcAddress = Tcb.Field("Path", TRUE).Field("SourceAddress", TRUE).Field("Identifier", TRUE).Field("Address").GetPtr();
                    }

                    if (DstAddress && g_Ext->m_Data->ReadVirtual(DstAddress, &NetworkEntry.Remote.IPv4_Addr, sizeof(NetworkEntry.Remote.IPv4_Addr), NULL) != S_OK) goto CleanUp;
                    if (SrcAddress && g_Ext->m_Data->ReadVirtual(SrcAddress, &NetworkEntry.Local.IPv4_Addr, sizeof(NetworkEntry.Local.IPv4_Addr), NULL) != S_OK) goto CleanUp;

                    ExtRemoteTyped OwningProcess("(nt!_EPROCESS *)@$extin", Tcb.Field("OwningProcess").GetPtr());

                    NetworkEntry.ProcessId = OwningProcess.Field("UniqueProcessId").GetPtr();
                    OwningProcess.Field("ImageFileName").GetString((LPSTR)NetworkEntry.ProcessName, sizeof(NetworkEntry.ProcessName));
                    NetworkEntries.push_back(NetworkEntry);
                }
            }
        }
    }

CleanUp:
    if (Table) free(Table);

    return NetworkEntries;
}