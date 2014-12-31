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
#include "CNdiskd.h"

// CAdapters constructor
CAdapters::CAdapters()
{
	// Initialize handler function address
	m_ptrPacketIndicateHandler = 0;
	m_ptrSendCompleteHandler = 0;
	m_ptrResetCompleteHandler = 0;
	m_ptrStatusHandler = 0;
	m_ptrStatusCompleteHandler = 0;
	m_ptrWanSendCompleteHandler = 0;
	m_ptrWanRcvHandler = 0;
	m_ptrWanRcvCompleteHandler = 0;
	m_ptrSendNetBufferListsCompleteHandler = 0;
	// Initialize NDIS start and end address
	m_ndisStartAddr = 0;
	m_ndisEndAddr = 0;
	// Initialize minidriver start and end address
	m_minidrvStartAddr = 0;
	m_minidrvEndAddr = 0;
	// Initialize heap to store protocol's information
	m_adaptername = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY|HEAP_NO_SERIALIZE , MAX_ADAPTER_NAME*sizeof(WCHAR));
#if DBG
	//g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "[DEBUG:%s] Allocate heap: %p\n", __FUNCTION__, m_adaptername);
#endif

}

// CAdapters destructor
CAdapters::~CAdapters()
{
	// Cleanup
#if DBG
	//g_Ext->m_Control->Output(DEBUG_OUTPUT_NORMAL, "[DEBUG:%s] Freeing protocol: %ls (%p)\n", __FUNCTION__, m_adaptername, m_adaptername);
#endif
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, m_adaptername);

}

VOID WINAPI CAdapters::SetAdapterName(PWSTR AdatperName)
{
	StringCchCopyExW(m_adaptername, MAX_ADAPTER_NAME, AdatperName, NULL, NULL, STRSAFE_FILL_BEHIND_NULL);
}

PWSTR WINAPI CAdapters::GetAdapterName()
{
	return m_adaptername;
}

BOOL WINAPI CAdapters::IsNdisFuncHandlerHooked(ULONG64 PtrHandler)
{
	BOOL boolIsHooked = (PtrHandler < m_ndisStartAddr) && (PtrHandler > m_ndisEndAddr);

	if (boolIsHooked)
		return true;
	else
		return false;
}

std::map<PCSTR, ULONG64>* WINAPI CAdapters::GetFunctionHandlers(std::map<PCSTR, ULONG64> *PtrHandlers)
{
	PtrHandlers->insert(std::make_pair("PacketIndicateHandler", m_ptrPacketIndicateHandler));
	PtrHandlers->insert(std::make_pair("ResetCompleteHandler", m_ptrResetCompleteHandler));
	PtrHandlers->insert(std::make_pair("WanRcvHandler", m_ptrWanRcvHandler));
	PtrHandlers->insert(std::make_pair("WanRcvCompleteHandler", m_ptrWanRcvCompleteHandler));
	PtrHandlers->insert(std::make_pair("WanSendCompleteHandler", m_ptrWanSendCompleteHandler));
	PtrHandlers->insert(std::make_pair("SendCompleteHandler", m_ptrSendCompleteHandler));
	PtrHandlers->insert(std::make_pair("SendNetBufferListsCompleteHandler", m_ptrSendNetBufferListsCompleteHandler));
	PtrHandlers->insert(std::make_pair("StatusCompleteHandler", m_ptrStatusCompleteHandler));
	PtrHandlers->insert(std::make_pair("StatusHandler", m_ptrStatusHandler));

	return PtrHandlers;
}