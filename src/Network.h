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

#include "MoonSolsDbgExt.h"

/*
16.kd:x86> dt nt!_RTL_DYNAMIC_HASH_TABLE_ENTRY
+0x000 Linkage          : _LIST_ENTRY
+0x010 Signature        : Uint8B

16.kd:x86> dt tcpip!_NL_PATH
+0x000 SourceAddress    : Ptr64 _NL_LOCAL_ADDRESS
+0x008 ScopeId          : SCOPE_ID
+0x010 DestinationAddress : Ptr64 UChar
16.kd:x86> dt tcpip!_NL_PATH -b
+0x000 SourceAddress    : Ptr64
+0x008 ScopeId          : SCOPE_ID
+0x000 Zone             : Pos 0, 28 Bits
+0x000 Level            : Pos 28, 4 Bits
+0x000 Value            : Uint4B
+0x010 DestinationAddress : Ptr64

kd> dt tcpip!PartitionTable
0x84767ac8
+0x000 Lock             : 0x84767800 _RTL_SCALABLE_MRSW_LOCK
+0x004 HashTables       : 0x84767940 _TCP_HASH_TABLES
+0x008 IpHashTables     : 0x84767a00 _TCP_HASH_TABLES
+0x00c TimerWheels      : 0x8476a008 _TCP_TIMER_WHEELS
+0x010 ReassemblyListHead : _LIST_ENTRY [ 0x84767ad8 - 0x84767ad8 ]
+0x018 DelayQueueEntry  : _SINGLE_LIST_ENTRY
+0x01c MppEnumerator    : _RTL_DYNAMIC_HASH_TABLE_ENUMERATOR
+0x030 PendingInsertProcessor : 0x20
+0x034 SynRcvdCount     : 0
+0x038 SynRcvdRetryCount : 0
+0x03c NextExpirationTick : 0n0
+0x040 InDelayQueue     : 0 ''
+0x041 NeedSynRcvdLimitCheck : 0 ''
+0x042 SynRcvdLimitExceeded : 0 ''
+0x043 InMppEvaluation  : 0 ''
+0x044 MppEvaluationComplete : 0 ''

16.kd:x86> dt tcpip!_TCB
   +0x000 SpinLock         : Uint8B
   +0x008 ReferenceCount   : Uint4B
   +0x010 Client           : Ptr64 _TCP_CLIENT
   +0x018 Af               : Ptr64 _TCP_AF
   +0x020 Path             : Ptr64 _NL_PATH
   +0x028 HashTableEntry   : _RTL_DYNAMIC_HASH_TABLE_ENTRY
   +0x040 IpHashTableEntry : _RTL_DYNAMIC_HASH_TABLE_ENTRY
   +0x058 EventDispatch    : Ptr64 _TL_CLIENT_CONNECT_DISPATCH
   +0x060 EventContext     : Ptr64 Void
   +0x058 RateLimitPathListEntry : _LIST_ENTRY
   +0x068 State            : TCB_STATE
   +0x06c LocalPort        : Uint2B
   +0x06e RemotePort       : Uint2B
   +0x06c TransportPortData : _TRANSPORT_PORT_DATA
   +0x070 ActiveOpen       : Pos 0, 1 Bit
   +0x070 Bound            : Pos 1, 1 Bit
   +0x070 Inserted         : Pos 2, 1 Bit
   +0x070 TimerInserted    : Pos 3, 1 Bit
   +0x070 Inet4Mapped      : Pos 4, 1 Bit
   +0x070 IsUnspecified    : Pos 5, 1 Bit
   +0x070 FinPended        : Pos 6, 1 Bit
   +0x070 FinAccepted      : Pos 7, 1 Bit
   +0x070 FinDelivered     : Pos 8, 1 Bit
   +0x070 ResetReceived    : Pos 9, 1 Bit
   +0x070 Aborted          : Pos 10, 1 Bit
   +0x070 ReceiveWindowStale : Pos 11, 1 Bit
   +0x070 SndUrpValid      : Pos 12, 1 Bit
   +0x070 NeedToOffload    : Pos 13, 1 Bit
   +0x070 NeedToUpload     : Pos 14, 1 Bit
   +0x070 NeedAck          : Pos 15, 1 Bit
   +0x070 NeedOutput       : Pos 16, 1 Bit
   +0x070 NeedKeepAlive    : Pos 17, 1 Bit
   +0x070 NeedNotifySendBacklog : Pos 18, 1 Bit
   +0x070 NeedReachabilityConfirmation : Pos 19, 1 Bit
   +0x070 NeedReachabilitySuspicion : Pos 20, 1 Bit
   +0x070 ForceOutput      : Pos 21, 1 Bit
   +0x070 InOutput         : Pos 22, 1 Bit
   +0x070 InNormalDelivery : Pos 23, 1 Bit
   +0x070 InUrgentDelivery : Pos 24, 1 Bit
   +0x070 InDelayQueue     : Pos 25, 1 Bit
   +0x070 InTimeout        : Pos 26, 1 Bit
   +0x070 InRecovery       : Pos 27, 1 Bit
   +0x070 InUrgentReception : Pos 28, 1 Bit
   +0x070 InUrgentInput    : Pos 29, 1 Bit
   +0x070 InActivation     : Pos 30, 1 Bit
   +0x070 FullSizeSegmentSent : Pos 31, 1 Bit
   +0x070 Flags            : Uint4B
   +0x074 Unsynchronized   : Pos 0, 1 Bit
   +0x074 Shutdown         : Pos 1, 1 Bit
   +0x074 FinSent          : Pos 2, 1 Bit
   +0x074 FinReceived      : Pos 3, 1 Bit
   +0x074 InReassembly     : Pos 4, 1 Bit
   +0x074 InSndWndProbe    : Pos 5, 1 Bit
   +0x074 Inconsistent     : Pos 6, 1 Bit
   +0x074 DupAckReceived   : Pos 7, 1 Bit
   +0x074 RcvUrpValid      : Pos 8, 1 Bit
   +0x074 InSpuriousRtoDetection : Pos 9, 2 Bits
   +0x074 InBHMode         : Pos 11, 1 Bit
   +0x074 InRttChangeDetection : Pos 12, 2 Bits
   +0x074 UseResilientTimeout : Pos 14, 1 Bit
   +0x074 InCarefulPath    : Uint2B
   +0x076 JoinPathPending  : Pos 0, 1 Bit
   +0x076 CancellationFlags : Uint2B
   +0x078 SndUna           : Uint4B
   +0x07c SndNxt           : Uint4B
   +0x080 SndMax           : Uint4B
   +0x084 SndUrp           : Uint4B
   +0x088 SndWL1           : Uint4B
   +0x08c SndConfirm       : Uint4B
   +0x090 SndWnd           : Uint4B
   +0x094 MaxSndWnd        : Uint4B
   +0x098 DupAckCount      : UChar
   +0x099 SendBacklogIndex : UChar
   +0x09a RemoteMss        : Uint2B
   +0x09c Mss              : Uint4B
   +0x0a0 AcksDelayed      : UChar
   +0x0a2 PseudoHeaderChecksum : Uint2B
   +0x0a4 SndWindScale     : UChar
   +0x0a5 RcvWindScale     : UChar
   +0x0a8 SndFirstFullSegment : Uint4B
   +0x0ac OriginalMss      : Uint4B
   +0x0a8 RateLimitProcessListEntry : _LIST_ENTRY
   +0x0b8 BHProbeCount     : UChar
   +0x0bc CWnd             : Uint4B
   +0x0c0 SsThresh         : Uint4B
   +0x0c8 CTcpDwndParameters : _CTCP_DWND_PARAMETERS
   +0x110 SendAvailable    : Uint8B
   +0x118 SendRequestHead  : Ptr64 _TCB_REQUEST_SEND
   +0x120 SendRequestTail  : Ptr64 _TCB_REQUEST_SEND
   +0x120 SendIdleTickCount : Uint4B
   +0x128 SndNxtRequest    : Ptr64 _TCB_REQUEST_SEND
   +0x130 SndNxtBytesLeft  : Uint8B
   +0x138 SndNxtMdl        : Ptr64 _MDL
   +0x140 SndNxtMdlOffset  : Uint4B
   +0x144 RcvNxt           : Uint4B
   +0x148 RcvUrpStart      : Uint4B
   +0x14c RcvUrpEnd        : Uint4B
   +0x150 RcvConfirm       : Uint4B
   +0x154 RcvWnd           : Uint4B
   +0x158 RcvWndTuningThreshold : Uint4B
   +0x15c RcvWndTuningThresholdExpiration : Uint4B
   +0x160 NormalDelivery   : _TCB_DELIVERY
   +0x1c0 UrgentDelivery   : Ptr64 _TCB_DELIVERY
   +0x1c8 Close            : <unnamed-tag>
   +0x1c8 CancelConnect    : <unnamed-tag>
   +0x1c8 Inspect          : <unnamed-tag>
   +0x1d8 ConnectRequest   : Ptr64 _TCB_REQUEST_CONNECT
   +0x1d8 DisconnectRequest : Ptr64 _TCB_REQUEST_DISCONNECT
   +0x1e0 AbortRequest     : Ptr64 _TCB_REQUEST_ABORT
   +0x1e0 WorkQueueEntry   : _SINGLE_LIST_ENTRY
   +0x1f0 DelayQueueEntry  : _SINGLE_LIST_ENTRY
   +0x1f0 TransferQueueEntry : _SLIST_ENTRY
   +0x200 SRtt             : Uint2B
   +0x202 RttVar           : Uint2B
   +0x204 RttSeq           : Uint4B
   +0x208 RttTickCount     : Uint4B
   +0x20c ResilientTimeout : Uint4B
   +0x204 TsRecent         : Uint4B
   +0x208 TsRecentTickCount : Uint4B
   +0x20c TsDelta          : Uint4B
   +0x210 LastTsSent       : Uint4B
   +0x214 LastAckSent      : Uint4B
   +0x218 TotalRT          : Uint4B
   +0x21c RexmitCount      : UChar
   +0x21d SndWndProbeCount : UChar
   +0x21e KaProbeCount     : UChar
   +0x21f DupSackCount     : UChar
   +0x220 WsdWsRestrictedByRexmitCount : Pos 0, 1 Bit
   +0x220 MppCandidate     : Pos 1, 1 Bit
   +0x220 MoreFlags        : Uint2B
   +0x224 FirstRttSampled  : Pos 0, 1 Bit
   +0x224 NotInHost        : Pos 1, 1 Bit
   +0x224 SegmentationOffload : Pos 2, 1 Bit
   +0x224 DenyOffload      : Pos 3, 1 Bit
   +0x224 ResetSent        : Pos 4, 1 Bit
   +0x224 SynRcvd          : Pos 5, 1 Bit
   +0x224 SynAckRetried    : Pos 6, 1 Bit
   +0x224 IsLoopback       : Pos 7, 1 Bit
   +0x224 InSwsAvoidance   : Pos 8, 1 Bit
   +0x224 InSynOrRstValidation : Pos 9, 1 Bit
   +0x224 InAutoKeepAlive  : Pos 10, 1 Bit
   +0x224 InTimedDisconnect : Pos 11, 1 Bit
   +0x224 InspectStream    : Pos 12, 1 Bit
   +0x224 SendBacklog      : Pos 13, 1 Bit
   +0x224 WfpRecommendsOffload : Pos 14, 1 Bit
   +0x224 EcnNegotiated    : Pos 15, 1 Bit
   +0x224 EcnEceNeeded     : Pos 16, 1 Bit
   +0x224 EcnCwrNeeded     : Pos 17, 1 Bit
   +0x224 CanFragment      : Pos 18, 1 Bit
   +0x224 IpOptionPresent  : Pos 19, 1 Bit
   +0x224 AckForFullSizeSegmentRcvd : Pos 20, 1 Bit
   +0x224 WsdInProgress    : Pos 21, 1 Bit
   +0x224 WsdImmediateAck  : Pos 22, 1 Bit
   +0x224 WsdMinSegCountRcvd : Pos 23, 2 Bits
   +0x224 ReceiverDetectionRttSampleCount : Pos 25, 3 Bits
   +0x224 ReceiverDetectionRoundCount : Pos 28, 3 Bits
   +0x224 WfpModified      : Pos 31, 1 Bit
   +0x224 AdditionalFlags  : Uint4B
   +0x228 EffectiveFamily  : Uint2B
   +0x230 PortEndpoint     : _INET_PORT_ENDPOINT
   +0x230 Listener         : Ptr64 _TCP_LISTENER
   +0x238 OwningProcess    : Ptr64 _EPROCESS
   +0x240 SecurityDescriptor : Ptr64 Void
   +0x248 CreationTime     : _LARGE_INTEGER
   +0x250 ServiceTag       : Ptr64 Void
   +0x258 InspectHandle    : Ptr64 Void
   +0x260 Options          : _TCP_OPTIONS
   +0x280 SessionState     : Ptr64 Void
   +0x288 BackFillLength   : Uint2B
   +0x290 CcmState         : Ptr64 Void
   +0x298 PathEpoch        : Int4B
   +0x2a0 NextHop          : Ptr64 _IP_NEXT_HOP_PRIVATE
   +0x2a8 Estats           : Ptr64 _TCB_ESTATS
   +0x2b0 OffloadContext   : Ptr64 Void
   +0x2b8 DmaProcessor     : Uint4B
   +0x2bc DmaTransferCount : Uint4B
   +0x2c0 Reassembly       : Ptr64 _TCB_REASSEMBLY
   +0x2c8 Recovery         : Ptr64 _TCB_RECOVERY
   +0x2d0 CwrMax           : Uint4B
   +0x2d8 ForwardListHead  : Ptr64 _NET_BUFFER_LIST
   +0x2e0 ForwardListTail  : Ptr64 _NET_BUFFER_LIST
   +0x2e8 TimerList        : _LIST_ENTRY
   +0x2f8 ExpirationTick   : Int4B
   +0x2fc TickArray        : [5] Int4B
   +0x2e8 TimerElement     : _RTL_TIMER_WHEEL_ENTRY
   
   
   kd> dt nt!_RTL_DYNAMIC_HASH_TABLE_ENTRY;
   +0x000 Linkage          : _LIST_ENTRY
   +0x008 Signature        : Uint4B
   kd> dt nt!_RTL_DYNAMIC_HASH_TABLE_ENTRY -b
   +0x000 Linkage          : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x008 Signature        : Uint4B
   kd>  dt tcpip!_NL_PATH
   +0x000 SourceAddress    : Ptr32 _NL_LOCAL_ADDRESS
   +0x004 ScopeId          : SCOPE_ID
   +0x008 DestinationAddress : Ptr32 UChar
   kd> dt tcpip!_TCB
   +0x000 SpinLock         : Uint4B
   +0x004 ReferenceCount   : Uint4B
   +0x008 Client           : Ptr32 _TCP_CLIENT
   +0x00c Af               : Ptr32 _TCP_AF
   +0x010 Path             : Ptr32 _NL_PATH
   +0x014 HashTableEntry   : _RTL_DYNAMIC_HASH_TABLE_ENTRY
   +0x020 IpHashTableEntry : _RTL_DYNAMIC_HASH_TABLE_ENTRY
   +0x02c EventDispatch    : Ptr32 _TL_CLIENT_CONNECT_DISPATCH
   +0x030 EventContext     : Ptr32 Void
   +0x02c RateLimitPathListEntry : _LIST_ENTRY
   +0x034 State            : TCB_STATE
   +0x038 LocalPort        : Uint2B
   +0x03a RemotePort       : Uint2B
   +0x038 TransportPortData : _TRANSPORT_PORT_DATA
   +0x03c ActiveOpen       : Pos 0, 1 Bit
   +0x03c Bound            : Pos 1, 1 Bit
   +0x03c Inserted         : Pos 2, 1 Bit
   +0x03c TimerInserted    : Pos 3, 1 Bit
   +0x03c Inet4Mapped      : Pos 4, 1 Bit
   +0x03c IsUnspecified    : Pos 5, 1 Bit
   +0x03c FinPended        : Pos 6, 1 Bit
   +0x03c FinAccepted      : Pos 7, 1 Bit
   +0x03c FinDelivered     : Pos 8, 1 Bit
   +0x03c ResetReceived    : Pos 9, 1 Bit
   +0x03c Aborted          : Pos 10, 1 Bit
   +0x03c ReceiveWindowStale : Pos 11, 1 Bit
   +0x03c SndUrpValid      : Pos 12, 1 Bit
   +0x03c NeedToOffload    : Pos 13, 1 Bit
   +0x03c NeedToUpload     : Pos 14, 1 Bit
   +0x03c NeedAck          : Pos 15, 1 Bit
   +0x03c NeedOutput       : Pos 16, 1 Bit
   +0x03c NeedKeepAlive    : Pos 17, 1 Bit
   +0x03c NeedNotifySendBacklog : Pos 18, 1 Bit
   +0x03c NeedReachabilityConfirmation : Pos 19, 1 Bit
   +0x03c NeedReachabilitySuspicion : Pos 20, 1 Bit
   +0x03c ForceOutput      : Pos 21, 1 Bit
   +0x03c InOutput         : Pos 22, 1 Bit
   +0x03c InNormalDelivery : Pos 23, 1 Bit
   +0x03c InUrgentDelivery : Pos 24, 1 Bit
   +0x03c InDelayQueue     : Pos 25, 1 Bit
   +0x03c InTimeout        : Pos 26, 1 Bit
   +0x03c InRecovery       : Pos 27, 1 Bit
   +0x03c InUrgentReception : Pos 28, 1 Bit
   +0x03c InUrgentInput    : Pos 29, 1 Bit
   +0x03c InActivation     : Pos 30, 1 Bit
   +0x03c FullSizeSegmentSent : Pos 31, 1 Bit
   +0x03c Flags            : Uint4B
   +0x040 Unsynchronized   : Pos 0, 1 Bit
   +0x040 Shutdown         : Pos 1, 1 Bit
   +0x040 FinSent          : Pos 2, 1 Bit
   +0x040 FinReceived      : Pos 3, 1 Bit
   +0x040 InReassembly     : Pos 4, 1 Bit
   +0x040 InSndWndProbe    : Pos 5, 1 Bit
   +0x040 Inconsistent     : Pos 6, 1 Bit
   +0x040 DupAckReceived   : Pos 7, 1 Bit
   +0x040 RcvUrpValid      : Pos 8, 1 Bit
   +0x040 InSpuriousRtoDetection : Pos 9, 2 Bits
   +0x040 InBHMode         : Pos 11, 1 Bit
   +0x040 InRttChangeDetection : Pos 12, 2 Bits
   +0x040 UseResilientTimeout : Pos 14, 1 Bit
   +0x040 InCarefulPath    : Uint2B
   +0x042 JoinPathPending  : Pos 0, 1 Bit
   +0x042 CancellationFlags : Uint2B
   +0x044 SndUna           : Uint4B
   +0x048 SndNxt           : Uint4B
   +0x04c SndMax           : Uint4B
   +0x050 SndUrp           : Uint4B
   +0x054 SndWL1           : Uint4B
   +0x058 SndConfirm       : Uint4B
   +0x05c SndWnd           : Uint4B
   +0x060 MaxSndWnd        : Uint4B
   +0x064 DupAckCount      : UChar
   +0x065 SendBacklogIndex : UChar
   +0x066 RemoteMss        : Uint2B
   +0x068 Mss              : Uint4B
   +0x06c AcksDelayed      : UChar
   +0x06e PseudoHeaderChecksum : Uint2B
   +0x070 SndWindScale     : UChar
   +0x071 RcvWindScale     : UChar
   +0x074 SndFirstFullSegment : Uint4B
   +0x078 OriginalMss      : Uint4B
   +0x074 RateLimitProcessListEntry : _LIST_ENTRY
   +0x07c BHProbeCount     : UChar
   +0x080 CWnd             : Uint4B
   +0x084 SsThresh         : Uint4B
   +0x088 CTcpDwndParameters : _CTCP_DWND_PARAMETERS
   +0x0c0 SendAvailable    : Uint4B
   +0x0c4 SendRequestHead  : Ptr32 _TCB_REQUEST_SEND
   +0x0c8 SendRequestTail  : Ptr32 _TCB_REQUEST_SEND
   +0x0c8 SendIdleTickCount : Uint4B
   +0x0cc SndNxtRequest    : Ptr32 _TCB_REQUEST_SEND
   +0x0d0 SndNxtBytesLeft  : Uint4B
   +0x0d4 SndNxtMdl        : Ptr32 _MDL
   +0x0d8 SndNxtMdlOffset  : Uint4B
   +0x0dc RcvNxt           : Uint4B
   +0x0e0 RcvUrpStart      : Uint4B
   +0x0e4 RcvUrpEnd        : Uint4B
   +0x0e8 RcvConfirm       : Uint4B
   +0x0ec RcvWnd           : Uint4B
   +0x0f0 RcvWndTuningThreshold : Uint4B
   +0x0f4 RcvWndTuningThresholdExpiration : Uint4B
   +0x0f8 NormalDelivery   : _TCB_DELIVERY
   +0x128 UrgentDelivery   : Ptr32 _TCB_DELIVERY
   +0x12c Close            : <unnamed-tag>
   +0x12c CancelConnect    : <unnamed-tag>
   +0x12c Inspect          : <unnamed-tag>
   +0x138 ConnectRequest   : Ptr32 _TCB_REQUEST_CONNECT
   +0x138 DisconnectRequest : Ptr32 _TCB_REQUEST_DISCONNECT
   +0x13c AbortRequest     : Ptr32 _TCB_REQUEST_ABORT
   +0x13c WorkQueueEntry   : _SINGLE_LIST_ENTRY
   +0x140 DelayQueueEntry  : _SINGLE_LIST_ENTRY
   +0x140 TransferQueueEntry : _SINGLE_LIST_ENTRY
   +0x144 SRtt             : Uint2B
   +0x146 RttVar           : Uint2B
   +0x148 RttSeq           : Uint4B
   +0x14c RttTickCount     : Uint4B
   +0x150 ResilientTimeout : Uint4B
   +0x148 TsRecent         : Uint4B
   +0x14c TsRecentTickCount : Uint4B
   +0x150 TsDelta          : Uint4B
   +0x154 LastTsSent       : Uint4B
   +0x158 LastAckSent      : Uint4B
   +0x15c TotalRT          : Uint4B
   +0x160 RexmitCount      : UChar
   +0x161 SndWndProbeCount : UChar
   +0x162 KaProbeCount     : UChar
   +0x163 DupSackCount     : UChar
   +0x164 WsdWsRestrictedByRexmitCount : Pos 0, 1 Bit
   +0x164 MppCandidate     : Pos 1, 1 Bit
   +0x164 MoreFlags        : Uint2B
   +0x168 FirstRttSampled  : Pos 0, 1 Bit
   +0x168 NotInHost        : Pos 1, 1 Bit
   +0x168 SegmentationOffload : Pos 2, 1 Bit
   +0x168 DenyOffload      : Pos 3, 1 Bit
   +0x168 ResetSent        : Pos 4, 1 Bit
   +0x168 SynRcvd          : Pos 5, 1 Bit
   +0x168 SynAckRetried    : Pos 6, 1 Bit
   +0x168 IsLoopback       : Pos 7, 1 Bit
   +0x168 InSwsAvoidance   : Pos 8, 1 Bit
   +0x168 InSynOrRstValidation : Pos 9, 1 Bit
   +0x168 InAutoKeepAlive  : Pos 10, 1 Bit
   +0x168 InTimedDisconnect : Pos 11, 1 Bit
   +0x168 InspectStream    : Pos 12, 1 Bit
   +0x168 SendBacklog      : Pos 13, 1 Bit
   +0x168 WfpRecommendsOffload : Pos 14, 1 Bit
   +0x168 EcnNegotiated    : Pos 15, 1 Bit
   +0x168 EcnEceNeeded     : Pos 16, 1 Bit
   +0x168 EcnCwrNeeded     : Pos 17, 1 Bit
   +0x168 CanFragment      : Pos 18, 1 Bit
   +0x168 IpOptionPresent  : Pos 19, 1 Bit
   +0x168 AckForFullSizeSegmentRcvd : Pos 20, 1 Bit
   +0x168 WsdInProgress    : Pos 21, 1 Bit
   +0x168 WsdImmediateAck  : Pos 22, 1 Bit
   +0x168 WsdMinSegCountRcvd : Pos 23, 2 Bits
   +0x168 ReceiverDetectionRttSampleCount : Pos 25, 3 Bits
   +0x168 ReceiverDetectionRoundCount : Pos 28, 3 Bits
   +0x168 WfpModified      : Pos 31, 1 Bit
   +0x168 AdditionalFlags  : Uint4B
   +0x16c EffectiveFamily  : Uint2B
   +0x170 PortEndpoint     : _INET_PORT_ENDPOINT
   +0x170 Listener         : Ptr32 _TCP_LISTENER
   +0x174 OwningProcess    : Ptr32 _EPROCESS
   +0x178 SecurityDescriptor : Ptr32 Void
   +0x180 CreationTime     : _LARGE_INTEGER
   +0x188 ServiceTag       : Ptr32 Void
   +0x18c InspectHandle    : Ptr32 Void
   +0x190 Options          : _TCP_OPTIONS
   +0x1ac SessionState     : Ptr32 Void
   +0x1b0 BackFillLength   : Uint2B
   +0x1b4 CcmState         : Ptr32 Void
   +0x1b8 PathEpoch        : Int4B
   +0x1bc NextHop          : Ptr32 _IP_NEXT_HOP_PRIVATE
   +0x1c0 Estats           : Ptr32 _TCB_ESTATS
   +0x1c4 OffloadContext   : Ptr32 Void
   +0x1c8 DmaProcessor     : Uint4B
   +0x1cc DmaTransferCount : Uint4B
   +0x1d0 Reassembly       : Ptr32 _TCB_REASSEMBLY
   +0x1d4 Recovery         : Ptr32 _TCB_RECOVERY
   +0x1d8 CwrMax           : Uint4B
   +0x1dc ForwardListHead  : Ptr32 _NET_BUFFER_LIST
   +0x1e0 ForwardListTail  : Ptr32 _NET_BUFFER_LIST
   +0x1e4 TimerList        : _LIST_ENTRY
   +0x1ec ExpirationTick   : Int4B
   +0x1f0 TickArray        : [5] Int4B
   +0x1e4 TimerElement     : _RTL_TIMER_WHEEL_ENTRY
   kd> dt tcpip!_TCB -b
   +0x000 SpinLock         : Uint4B
   +0x004 ReferenceCount   : Uint4B
   +0x008 Client           : Ptr32
   +0x00c Af               : Ptr32
   +0x010 Path             : Ptr32
   +0x014 HashTableEntry   : _RTL_DYNAMIC_HASH_TABLE_ENTRY
   +0x000 Linkage          : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x008 Signature        : Uint4B
   +0x020 IpHashTableEntry : _RTL_DYNAMIC_HASH_TABLE_ENTRY
   +0x000 Linkage          : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x008 Signature        : Uint4B
   +0x02c EventDispatch    : Ptr32
   +0x030 EventContext     : Ptr32
   +0x02c RateLimitPathListEntry : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x034 State            :
   TcbClosedState = 0n0
   TcbListenState = 0n1
   TcbSynSentState = 0n2
   TcbSynRcvdState = 0n3
   TcbEstablishedState = 0n4
   TcbFinWait1State = 0n5
   TcbFinWait2State = 0n6
   TcbCloseWaitState = 0n7
   TcbClosingState = 0n8
   TcbLastAckState = 0n9
   TcbTimeWaitState = 0n10
   TcbMaximumState = 0n11
   +0x038 LocalPort        : Uint2B
   +0x03a RemotePort       : Uint2B
   +0x038 TransportPortData : _TRANSPORT_PORT_DATA
   +0x000 SourcePort       : Uint2B
   +0x002 DestinationPort  : Uint2B
   +0x03c ActiveOpen       : Pos 0, 1 Bit
   +0x03c Bound            : Pos 1, 1 Bit
   +0x03c Inserted         : Pos 2, 1 Bit
   +0x03c TimerInserted    : Pos 3, 1 Bit
   +0x03c Inet4Mapped      : Pos 4, 1 Bit
   +0x03c IsUnspecified    : Pos 5, 1 Bit
   +0x03c FinPended        : Pos 6, 1 Bit
   +0x03c FinAccepted      : Pos 7, 1 Bit
   +0x03c FinDelivered     : Pos 8, 1 Bit
   +0x03c ResetReceived    : Pos 9, 1 Bit
   +0x03c Aborted          : Pos 10, 1 Bit
   +0x03c ReceiveWindowStale : Pos 11, 1 Bit
   +0x03c SndUrpValid      : Pos 12, 1 Bit
   +0x03c NeedToOffload    : Pos 13, 1 Bit
   +0x03c NeedToUpload     : Pos 14, 1 Bit
   +0x03c NeedAck          : Pos 15, 1 Bit
   +0x03c NeedOutput       : Pos 16, 1 Bit
   +0x03c NeedKeepAlive    : Pos 17, 1 Bit
   +0x03c NeedNotifySendBacklog : Pos 18, 1 Bit
   +0x03c NeedReachabilityConfirmation : Pos 19, 1 Bit
   +0x03c NeedReachabilitySuspicion : Pos 20, 1 Bit
   +0x03c ForceOutput      : Pos 21, 1 Bit
   +0x03c InOutput         : Pos 22, 1 Bit
   +0x03c InNormalDelivery : Pos 23, 1 Bit
   +0x03c InUrgentDelivery : Pos 24, 1 Bit
   +0x03c InDelayQueue     : Pos 25, 1 Bit
   +0x03c InTimeout        : Pos 26, 1 Bit
   +0x03c InRecovery       : Pos 27, 1 Bit
   +0x03c InUrgentReception : Pos 28, 1 Bit
   +0x03c InUrgentInput    : Pos 29, 1 Bit
   +0x03c InActivation     : Pos 30, 1 Bit
   +0x03c FullSizeSegmentSent : Pos 31, 1 Bit
   +0x03c Flags            : Uint4B
   +0x040 Unsynchronized   : Pos 0, 1 Bit
   +0x040 Shutdown         : Pos 1, 1 Bit
   +0x040 FinSent          : Pos 2, 1 Bit
   +0x040 FinReceived      : Pos 3, 1 Bit
   +0x040 InReassembly     : Pos 4, 1 Bit
   +0x040 InSndWndProbe    : Pos 5, 1 Bit
   +0x040 Inconsistent     : Pos 6, 1 Bit
   +0x040 DupAckReceived   : Pos 7, 1 Bit
   +0x040 RcvUrpValid      : Pos 8, 1 Bit
   +0x040 InSpuriousRtoDetection : Pos 9, 2 Bits
   +0x040 InBHMode         : Pos 11, 1 Bit
   +0x040 InRttChangeDetection : Pos 12, 2 Bits
   +0x040 UseResilientTimeout : Pos 14, 1 Bit
   +0x040 InCarefulPath    : Uint2B
   +0x042 JoinPathPending  : Pos 0, 1 Bit
   +0x042 CancellationFlags : Uint2B
   +0x044 SndUna           : Uint4B
   +0x048 SndNxt           : Uint4B
   +0x04c SndMax           : Uint4B
   +0x050 SndUrp           : Uint4B
   +0x054 SndWL1           : Uint4B
   +0x058 SndConfirm       : Uint4B
   +0x05c SndWnd           : Uint4B
   +0x060 MaxSndWnd        : Uint4B
   +0x064 DupAckCount      : UChar
   +0x065 SendBacklogIndex : UChar
   +0x066 RemoteMss        : Uint2B
   +0x068 Mss              : Uint4B
   +0x06c AcksDelayed      : UChar
   +0x06e PseudoHeaderChecksum : Uint2B
   +0x070 SndWindScale     : UChar
   +0x071 RcvWindScale     : UChar
   +0x074 SndFirstFullSegment : Uint4B
   +0x078 OriginalMss      : Uint4B
   +0x074 RateLimitProcessListEntry : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x07c BHProbeCount     : UChar
   +0x080 CWnd             : Uint4B
   +0x084 SsThresh         : Uint4B
   +0x088 CTcpDwndParameters : _CTCP_DWND_PARAMETERS
   +0x000 DWnd             : Uint4B
   +0x004 Increment        : Uint4B
   +0x008 SndNxt           : Int2B
   +0x00a AckNxt           : Int2B
   +0x00c RoundEnd         : Int2B
   +0x00e NumberOfRttSamples : Int2B
   +0x010 AggregatedRttSum : Uint4B
   +0x014 BaseRtt          : Uint4B
   +0x018 AllocatedBlocks  : Pos 0, 4 Bits
   +0x018 AssignedBlocks   : Pos 4, 4 Bits
   +0x018 RttSampleBlocks  : Uint2B
   +0x01c SamplingInterval : Uint4B
   +0x020 NextSample       : Uint4B
   +0x024 RttSampleTable   : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x02c AverageBacklog   : Uint4B
   +0x030 AverageBacklogAcrossLFP : Uint4B
   +0x034 Gamma            : Uint4B
   +0x0c0 SendAvailable    : Uint4B
   +0x0c4 SendRequestHead  : Ptr32
   +0x0c8 SendRequestTail  : Ptr32
   +0x0c8 SendIdleTickCount : Uint4B
   +0x0cc SndNxtRequest    : Ptr32
   +0x0d0 SndNxtBytesLeft  : Uint4B
   +0x0d4 SndNxtMdl        : Ptr32
   +0x0d8 SndNxtMdlOffset  : Uint4B
   +0x0dc RcvNxt           : Uint4B
   +0x0e0 RcvUrpStart      : Uint4B
   +0x0e4 RcvUrpEnd        : Uint4B
   +0x0e8 RcvConfirm       : Uint4B
   +0x0ec RcvWnd           : Uint4B
   +0x0f0 RcvWndTuningThreshold : Uint4B
   +0x0f4 RcvWndTuningThresholdExpiration : Uint4B
   +0x0f8 NormalDelivery   : _TCB_DELIVERY
   +0x000 DeliveryBlock    : Ptr32
   +0x004 ReceiveRequestHead : Ptr32
   +0x008 ReceiveRequestTail : Ptr32
   +0x00c InputAvailable   : Uint4B
   +0x010 InputOutstanding : Uint4B
   +0x014 InputHead        : _TCB_INPUT
   +0x000 Next             : Ptr32
   +0x004 Head             : Ptr32
   +0x008 Tail             : Ptr32
   +0x020 InputTail        : Ptr32
   +0x024 InputOutstandingDelta : Int4B
   +0x028 InputInspecting  : Uint4B
   +0x02c CantIndicateData : Pos 0, 1 Bit
   +0x02c InOffloadIndication : Pos 1, 1 Bit
   +0x02c IndicationsBuffered : Pos 2, 3 Bits
   +0x02c MustOffloadReceive : Pos 5, 1 Bit
   +0x02c DmaFlushRequired : Pos 6, 1 Bit
   +0x02c DeliveryFlags    : UChar
   +0x128 UrgentDelivery   : Ptr32
   +0x12c Close            : <unnamed-tag>
   +0x000 RequestComplete  : Ptr32
   +0x004 RequestContext   : Ptr32
   +0x12c CancelConnect    : <unnamed-tag>
   +0x000 Unused           : Ptr32
   +0x004 Processor        : Uint4B
   +0x008 PostInspection   : UChar
   +0x009 ConnectCancelled : UChar
   +0x12c Inspect          : <unnamed-tag>
   +0x000 Key              : Uint4B
   +0x004 SerialNumber     : Uint4B
   +0x138 ConnectRequest   : Ptr32
   +0x138 DisconnectRequest : Ptr32
   +0x13c AbortRequest     : Ptr32
   +0x13c WorkQueueEntry   : _SINGLE_LIST_ENTRY
   +0x000 Next             : Ptr32
   +0x140 DelayQueueEntry  : _SINGLE_LIST_ENTRY
   +0x000 Next             : Ptr32
   +0x140 TransferQueueEntry : _SINGLE_LIST_ENTRY
   +0x000 Next             : Ptr32
   +0x144 SRtt             : Uint2B
   +0x146 RttVar           : Uint2B
   +0x148 RttSeq           : Uint4B
   +0x14c RttTickCount     : Uint4B
   +0x150 ResilientTimeout : Uint4B
   +0x148 TsRecent         : Uint4B
   +0x14c TsRecentTickCount : Uint4B
   +0x150 TsDelta          : Uint4B
   +0x154 LastTsSent       : Uint4B
   +0x158 LastAckSent      : Uint4B
   +0x15c TotalRT          : Uint4B
   +0x160 RexmitCount      : UChar
   +0x161 SndWndProbeCount : UChar
   +0x162 KaProbeCount     : UChar
   +0x163 DupSackCount     : UChar
   +0x164 WsdWsRestrictedByRexmitCount : Pos 0, 1 Bit
   +0x164 MppCandidate     : Pos 1, 1 Bit
   +0x164 MoreFlags        : Uint2B
   +0x168 FirstRttSampled  : Pos 0, 1 Bit
   +0x168 NotInHost        : Pos 1, 1 Bit
   +0x168 SegmentationOffload : Pos 2, 1 Bit
   +0x168 DenyOffload      : Pos 3, 1 Bit
   +0x168 ResetSent        : Pos 4, 1 Bit
   +0x168 SynRcvd          : Pos 5, 1 Bit
   +0x168 SynAckRetried    : Pos 6, 1 Bit
   +0x168 IsLoopback       : Pos 7, 1 Bit
   +0x168 InSwsAvoidance   : Pos 8, 1 Bit
   +0x168 InSynOrRstValidation : Pos 9, 1 Bit
   +0x168 InAutoKeepAlive  : Pos 10, 1 Bit
   +0x168 InTimedDisconnect : Pos 11, 1 Bit
   +0x168 InspectStream    : Pos 12, 1 Bit
   +0x168 SendBacklog      : Pos 13, 1 Bit
   +0x168 WfpRecommendsOffload : Pos 14, 1 Bit
   +0x168 EcnNegotiated    : Pos 15, 1 Bit
   +0x168 EcnEceNeeded     : Pos 16, 1 Bit
   +0x168 EcnCwrNeeded     : Pos 17, 1 Bit
   +0x168 CanFragment      : Pos 18, 1 Bit
   +0x168 IpOptionPresent  : Pos 19, 1 Bit
   +0x168 AckForFullSizeSegmentRcvd : Pos 20, 1 Bit
   +0x168 WsdInProgress    : Pos 21, 1 Bit
   +0x168 WsdImmediateAck  : Pos 22, 1 Bit
   +0x168 WsdMinSegCountRcvd : Pos 23, 2 Bits
   +0x168 ReceiverDetectionRttSampleCount : Pos 25, 3 Bits
   +0x168 ReceiverDetectionRoundCount : Pos 28, 3 Bits
   +0x168 WfpModified      : Pos 31, 1 Bit
   +0x168 AdditionalFlags  : Uint4B
   +0x16c EffectiveFamily  : Uint2B
   +0x170 PortEndpoint     : _INET_PORT_ENDPOINT
   +0x000 Next             : Ptr32
   +0x170 Listener         : Ptr32
   +0x174 OwningProcess    : Ptr32
   +0x178 SecurityDescriptor : Ptr32
   +0x180 CreationTime     : _LARGE_INTEGER
   +0x000 LowPart          : Uint4B
   +0x004 HighPart         : Int4B
   +0x000 u                : <unnamed-tag>
   +0x000 LowPart          : Uint4B
   +0x004 HighPart         : Int4B
   +0x000 QuadPart         : Int8B
   +0x188 ServiceTag       : Ptr32
   +0x18c InspectHandle    : Ptr32
   +0x190 Options          : _TCP_OPTIONS
   +0x000 StdUrgSet        : Pos 0, 1 Bit
   +0x000 KaSet            : Pos 1, 1 Bit
   +0x000 RcvBufSet        : Pos 2, 1 Bit
   +0x000 Sack             : Pos 3, 1 Bit
   +0x000 TimestampsSet    : Pos 4, 1 Bit
   +0x000 Timestamps       : Pos 5, 1 Bit
   +0x000 WindowScaling    : Pos 6, 1 Bit
   +0x000 NoDelay          : Pos 7, 1 Bit
   +0x001 NoUrg            : Pos 0, 1 Bit
   +0x001 StdUrg           : Pos 1, 1 Bit
   +0x001 Expedited1122    : Pos 2, 1 Bit
   +0x001 Inet6Only        : Pos 3, 1 Bit
   +0x001 KeepAlive        : Pos 4, 1 Bit
   +0x001 OobInline        : Pos 5, 1 Bit
   +0x001 ConditionalAccept : Pos 6, 1 Bit
   +0x001 PauseAccept      : Pos 7, 1 Bit
   +0x002 ReuseAddr        : Pos 0, 1 Bit
   +0x002 ExclusiveAddrUse : Pos 1, 1 Bit
   +0x002 AtMark           : Pos 2, 1 Bit
   +0x002 PMtuDiscovery    : Pos 3, 1 Bit
   +0x002 NoSynRetries     : Pos 4, 1 Bit
   +0x002 DelayFinAck      : Pos 5, 1 Bit
   +0x002 DontRoute        : Pos 6, 1 Bit
   +0x003 OffloadPreference : Pos 0, 2 Bits
   +0x003 RandomizePort    : Pos 2, 1 Bit
   +0x003 CongestionAlgorithm : Pos 3, 3 Bits
   +0x003 AllowRcvBufReductions : Pos 6, 1 Bit
   +0x004 AutotuningPreference : Pos 0, 2 Bits
   +0x004 DcaSet           : Pos 2, 1 Bit
   +0x004 Dca              : Pos 3, 1 Bit
   +0x004 PortScalability  : Pos 4, 1 Bit
   +0x006 EstatsData       : Pos 0, 1 Bit
   +0x006 EstatsPath       : Pos 1, 1 Bit
   +0x006 EstatsSndCong    : Pos 2, 1 Bit
   +0x006 EstatsSendBuff   : Pos 3, 1 Bit
   +0x006 EstatsObsRec     : Pos 4, 1 Bit
   +0x006 EstatsRec        : Pos 5, 1 Bit
   +0x006 EstatsFineRtt    : Pos 6, 1 Bit
   +0x006 EstatsSndBw      : Pos 7, 1 Bit
   +0x006 EstatsRcvBw      : Pos 8, 1 Bit
   +0x006 EstatsRcvWndTuning : Pos 9, 1 Bit
   +0x006 EstatsTrace      : Pos 10, 1 Bit
   +0x006 Estats           : Uint2B
   +0x008 DelayedAckTicks  : UChar
   +0x009 DelayedAckFrequency : UChar
   +0x00c RcvBuf           : Uint4B
   +0x010 KaTimeout        : Uint4B
   +0x014 KaInterval       : Uint4B
   +0x018 MaxRT            : Uint4B
   +0x1ac SessionState     : Ptr32
   +0x1b0 BackFillLength   : Uint2B
   +0x1b4 CcmState         : Ptr32
   +0x1b8 PathEpoch        : Int4B
   +0x1bc NextHop          : Ptr32
   +0x1c0 Estats           : Ptr32
   +0x1c4 OffloadContext   : Ptr32
   +0x1c8 DmaProcessor     : Uint4B
   +0x1cc DmaTransferCount : Uint4B
   +0x1d0 Reassembly       : Ptr32
   +0x1d4 Recovery         : Ptr32
   +0x1d8 CwrMax           : Uint4B
   +0x1dc ForwardListHead  : Ptr32
   +0x1e0 ForwardListTail  : Ptr32
   +0x1e4 TimerList        : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x1ec ExpirationTick   : Int4B
   +0x1f0 TickArray        : Int4B
   +0x1e4 TimerElement     : _RTL_TIMER_WHEEL_ENTRY
   +0x000 TimerList        : _LIST_ENTRY
   +0x000 Flink            : Ptr32
   +0x004 Blink            : Ptr32
   +0x008 ExpirationTick   : Int4B
   +0x00c TickArray        : Int4B
   */

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
typedef struct DECLSPEC_CACHEALIGN _TCP_HASH_TABLES {
    RTL_DYNAMIC_HASH_TABLE TcbTable;
    RTL_DYNAMIC_HASH_TABLE TimeWaitTcbTable;
    RTL_DYNAMIC_HASH_TABLE StandbyTcbTable;
    RTL_DYNAMIC_HASH_TABLE SynTcbTable;
} TCP_HASH_TABLES, *PTCP_HASH_TABLES;

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