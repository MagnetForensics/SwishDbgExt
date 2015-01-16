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

#ifndef _CMINIDRIVER_H_
#define _CMINIDRIVER_H_

#define MAX_MINIDRV_NAME 100

class CMinidriver
{
public:
    CMinidriver(ULONG64);
    ~CMinidriver();
    BOOL WINAPI IsHandlerHooked(ULONG64);
    PWSTR WINAPI GetMDriverName();
    ULONG64 WINAPI GetDriverStartAddr();
    ULONG64 WINAPI GetDriverEndAddr();
    std::map<PCSTR, ULONG64>* WINAPI GetFunctionHandlers(std::map<PCSTR, ULONG64>*);
    ULONG64 m_minidrvaddr;

    // Only partial handler functions that are known to be targeted on Minidriver
    ULONG64 m_ptrCheckForHangHandler;
    ULONG64 m_ptrDisableInterruptHandler;
    ULONG64 m_ptrEnableInterruptHandler;
    ULONG64 m_ptrHaltHandler;
    ULONG64 m_ptrHandleInterruptHandler;
    ULONG64 m_ptrInitializeHandler;
    ULONG64 m_ptrIsrHandler;
    ULONG64 m_ptrQueryInformationHandler;
    ULONG64 m_ptrReconfigureHandler;
    ULONG64 m_ptrResetHandler;
    ULONG64 m_ptrSendHandler;
    ULONG64 m_ptrWanSendHandler;
    ULONG64 m_ptrSetInformationHandler;
    ULONG64 m_ptrTransferDataHandler;
    ULONG64 m_ptrWanTransferDataHandler;
    ULONG64 m_ptrReturnPacketHandler;
    ULONG64 m_ptrSendPacketsHandler;
    ULONG64 m_ptrAllocateCompleteHandler;
    ULONG64 m_ptrCancelSendPacketsHandler;
    ULONG64 m_ptrPnpEventNotifyHandler;
    ULONG64 m_ptrAdapterShutdownHandler;
private:
    PWSTR m_drivername;
    ULONG64 m_drvstartaddr;
    ULONG64 m_drvendaddr;
};

#endif // _CMINIDRIVER_H_