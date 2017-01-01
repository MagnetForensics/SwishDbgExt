/*++
    A NDIS hook scan extension to existing Incident Response & Digital Forensics Debugging Extension

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

#ifndef _CPROTOCOLS_H_
#define _CPROTOCOLS_H_

#define MAX_PROTOCOL_NAME 100
#define MAX_MODULE_NAME 256

class CProtocols
{
public:
    CProtocols();
    ~CProtocols();
    BOOL WINAPI IsProtocolFuncHandlerHooked(ULONG64);
    VOID WINAPI SetProtocolName(PWSTR);
    PWSTR WINAPI GetProtocolName();
    VOID WINAPI SetPtrHandler(ULONG64);
    ULONG64 WINAPI GetPtrHandler();
    std::map<PCSTR, ULONG64>* WINAPI GetFunctionHandlers(std::map<PCSTR, ULONG64>*);
    UCHAR m_majorversion;
    UCHAR m_minorversion;
    ULONG64 m_protocolStartAddr;
    ULONG64 m_protocolEndAddr;
    PSTR m_ModuleName;
    // Only partial handler functions that are known to be targeted
    ULONG64 m_ptrReceiveHandler;
    ULONG64 m_ptrReceivePacketHandler;
    ULONG64 m_ptrReceiveCompleteHandler;
    ULONG64 m_ptrWanReceiveHandler;
    ULONG64 m_ptrResetCompleteHandler;
    ULONG64 m_ptrWanTransferDataCompleteHandler;
    ULONG64 m_ptrTransferDataCompleteHandler;
    ULONG64 m_ptrWanSendCompleteHandler;
    ULONG64 m_ptrSendCompleteHandler;
    ULONG64 m_ptrCloseAdapterCompleteHandler;
    ULONG64 m_ptrOpenAdapterCompleteHandler;
    ULONG64 m_ptrSendNetBufferListsCompleteHandler;
    ULONG64 m_ptrReceiveNetBufferListsHandler;
    ULONG64 m_ptrStatusCompleteHandler;
    ULONG64 m_ptrStatusHandler;
    ULONG64 m_ptrStatusHandlerEx;
    ULONG64 m_ptrRequestCompleteHandler;

private:
    PWSTR m_protocolname;
};

#endif // _CPROTOCOLS_H_