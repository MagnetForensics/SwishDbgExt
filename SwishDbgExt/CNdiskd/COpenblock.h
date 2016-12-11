/*++
    A NDIS hook scan extension to existing MoonSols Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2014 wLcY (@x9090)

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
--*/

#ifndef _COPENBLOCKS_H_
#define _COPENBLOCKS_H_

#define MAX_PROTOCOL_NAME 100
#define MAX_ADAPTER_NAME 500
#define MAX_BINDING_NAME 1000

class COpenblock
{
public:
    COpenblock(ULONG64);
    ~COpenblock();
    BOOL WINAPI IsHandlerHooked(ULONG64);
    ULONG64 WINAPI GetMiniDriverStartAddr();
    ULONG64 WINAPI GetMiniDriverEndAddr();
    VOID WINAPI SetBinderName(PWSTR);
    PWSTR WINAPI GetBinderName();
    PWSTR WINAPI GetProtocolName();
    PWSTR WINAPI GetAdpaterName();
    std::map<PCSTR, ULONG64>* WINAPI GetFunctionHandlers(std::map<PCSTR, ULONG64>*);
    ULONG64 m_binderAddress;
    // Will be used in IsHandlerHooked
    ULONG64 m_ndisStartAddr;
    ULONG64 m_ndisEndAddr;
    ULONG64 m_bindProtocolHandlerStartAddr;
    ULONG64 m_bindProtocolHandlerEndAddr;
    ULONG64 m_bindAdapterHandlerStartAddr;
    ULONG64 m_bindAdapterHandlerEndAddr;
    // Only partial handler functions that are known to be targeted on NDIS library
    ULONG64 m_ptrSendHandler;
    ULONG64 m_ptrSendCompleteHandler;
    ULONG64 m_ptrSendPacketsHandler;
    ULONG64 m_ptrReceiveHandler;
    ULONG64 m_ptrReceiveCompleteHandler;
    ULONG64 m_ptrWanReceiveHandler;
    ULONG64 m_ptrRequestCompleteHandler;
    ULONG64 m_ptrResetCompleteHandler;
    ULONG64 m_ptrReceivePacketHandler;
    ULONG64 m_ptrStatusHandler;
    ULONG64 m_ptrStatusCompleteHandler;
    ULONG64 m_ptrWanSendHandler;
    // Available on NDIS6.x
    ULONG64 m_ptrReceiveNetBufferLists;
private:
    PWSTR m_bindingname;
    PWSTR m_protocolname;
    PWSTR m_adaptername;
};

#endif // _COPENBLOCKS_H_