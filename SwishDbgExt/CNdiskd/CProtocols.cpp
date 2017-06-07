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

#include "stdafx.h"
#include "CNdiskd.h"

// CProtocols constructor
CProtocols::CProtocols()
{
	m_majorversion = 0;
	m_minorversion = 0;
	m_protocolStartAddr = 0;
	m_protocolEndAddr = 0;
	m_ptrReceiveHandler = 0;
	m_ptrReceivePacketHandler = 0;
	m_ptrReceiveCompleteHandler = 0;
	m_ptrWanReceiveHandler = 0;
	m_ptrResetCompleteHandler = 0;
	m_ptrWanTransferDataCompleteHandler = 0;
	m_ptrTransferDataCompleteHandler = 0;
	m_ptrWanSendCompleteHandler = 0;
	m_ptrSendCompleteHandler = 0;
	m_ptrCloseAdapterCompleteHandler = 0;
	m_ptrOpenAdapterCompleteHandler = 0;
	m_ptrSendNetBufferListsCompleteHandler = 0;
	m_ptrReceiveNetBufferListsHandler = 0;
	m_ptrStatusCompleteHandler = 0;
	m_ptrStatusHandler = 0;
	m_ptrStatusHandlerEx = 0;
	m_ptrRequestCompleteHandler = 0;
	// Initialize heap to store protocol's information
	m_protocolname = (PWSTR)malloc(MAX_PROTOCOL_NAME*sizeof(WCHAR));
	m_ModuleName = (PSTR)malloc(MAX_MODULE_NAME);
}

// CProtocols destructor
CProtocols::~CProtocols()
{
	// Cleanup
	free(m_protocolname);
	free(m_ModuleName);
}

VOID WINAPI CProtocols::SetProtocolName(PWSTR ProtocolName)
{
	StringCchCopyW(m_protocolname, MAX_PROTOCOL_NAME, ProtocolName);
}

PWSTR WINAPI CProtocols::GetProtocolName()
{
	return m_protocolname;
}

VOID WINAPI CProtocols::SetPtrHandler(ULONG64 Handler)
{
    UNREFERENCED_PARAMETER(Handler);
}

BOOL WINAPI CProtocols::IsProtocolFuncHandlerHooked(ULONG64 PtrHandler)
{
	BOOL boolIsHooked = (PtrHandler < m_protocolStartAddr) && (PtrHandler > m_protocolEndAddr);

	if (boolIsHooked)
		return true;
	else
		return false;
}

std::map<PCSTR, ULONG64>* WINAPI CProtocols::GetFunctionHandlers(std::map<PCSTR, ULONG64> *PtrHandlers)
{
	PtrHandlers->insert(std::make_pair("ReceiveHandler", m_ptrReceiveHandler));
	PtrHandlers->insert(std::make_pair("ReceivePacketHandler", m_ptrReceivePacketHandler));
	PtrHandlers->insert(std::make_pair("ReceiveCompleteHandler", m_ptrReceiveCompleteHandler));
	PtrHandlers->insert(std::make_pair("WanReceiveHandler", m_ptrWanReceiveHandler));
	PtrHandlers->insert(std::make_pair("ResetCompleteHandler", m_ptrResetCompleteHandler));
	PtrHandlers->insert(std::make_pair("WanTransferDataCompleteHandler", m_ptrWanTransferDataCompleteHandler));
	PtrHandlers->insert(std::make_pair("TransferDataCompleteHandler", m_ptrTransferDataCompleteHandler));
	PtrHandlers->insert(std::make_pair("WanSendCompleteHandler", m_ptrWanSendCompleteHandler));
	PtrHandlers->insert(std::make_pair("SendCompleteHandler", m_ptrSendCompleteHandler));
	PtrHandlers->insert(std::make_pair("CloseAdapterCompleteHandler", m_ptrCloseAdapterCompleteHandler));
	PtrHandlers->insert(std::make_pair("OpenAdapterCompleteHandler", m_ptrOpenAdapterCompleteHandler));
	PtrHandlers->insert(std::make_pair("SendNetBufferListsCompleteHandler", m_ptrSendNetBufferListsCompleteHandler));
	PtrHandlers->insert(std::make_pair("ReceiveNetBufferListsHandler", m_ptrReceiveNetBufferListsHandler));
	PtrHandlers->insert(std::make_pair("StatusCompleteHandler", m_ptrStatusCompleteHandler));
	PtrHandlers->insert(std::make_pair("StatusHandler", m_ptrStatusHandler));
	PtrHandlers->insert(std::make_pair("StatusHandlerEx", m_ptrStatusHandlerEx));
	PtrHandlers->insert(std::make_pair("RequestCompleteHandler", m_ptrRequestCompleteHandler));

	return PtrHandlers;
}