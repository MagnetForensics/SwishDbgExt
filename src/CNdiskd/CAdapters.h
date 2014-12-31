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
#ifndef _CADAPTERS_H_
#define _CADAPTERS_H_

#define MAX_ADAPTER_NAME 500

class CAdapters 
{
public:
	CAdapters();
	~CAdapters();
	BOOL WINAPI IsNdisFuncHandlerHooked(ULONG64);
	VOID WINAPI SetAdapterName(PWSTR);
	PWSTR WINAPI GetAdapterName();
	std::map<PCSTR, ULONG64>* WINAPI GetFunctionHandlers(std::map<PCSTR,ULONG64>*);
	ULONG64 m_ndisStartAddr;
	ULONG64 m_ndisEndAddr;
	ULONG64 m_minidrvStartAddr;
	ULONG64 m_minidrvEndAddr;
	// Only partial handler functions that are known to be targeted on NDIS library
	ULONG64 m_ptrPacketIndicateHandler;
	ULONG64 m_ptrSendCompleteHandler;
	ULONG64 m_ptrResetCompleteHandler;
	ULONG64 m_ptrStatusHandler;
	ULONG64 m_ptrStatusCompleteHandler;
	ULONG64 m_ptrWanSendCompleteHandler;
	ULONG64 m_ptrWanRcvHandler;
	ULONG64 m_ptrWanRcvCompleteHandler;
	ULONG64 m_ptrSendNetBufferListsCompleteHandler;
private:
	PWSTR m_adaptername;
};

#endif // _CADAPTERS_H_