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

// CMinidriver constructor
CMinidriver::CMinidriver(ULONG64 MinidriverAddr)
{
    // Initialize minidriver ptr
    m_minidrvaddr = MinidriverAddr;

    // Initialize handler function address
    m_ptrCheckForHangHandler = 0;
    m_ptrDisableInterruptHandler = 0;
    m_ptrEnableInterruptHandler = 0;
    m_ptrHaltHandler = 0;
    m_ptrHandleInterruptHandler = 0;
    m_ptrInitializeHandler = 0;
    m_ptrIsrHandler = 0;
    m_ptrQueryInformationHandler = 0;
    m_ptrReconfigureHandler = 0;
    m_ptrResetHandler = 0;
    m_ptrSendHandler = 0;
    m_ptrWanSendHandler = 0;
    m_ptrSetInformationHandler = 0;
    m_ptrTransferDataHandler = 0;
    m_ptrWanTransferDataHandler = 0;
    m_ptrReturnPacketHandler = 0;
    m_ptrSendPacketsHandler = 0;
    m_ptrAllocateCompleteHandler = 0;
    m_ptrCancelSendPacketsHandler = 0;
    m_ptrPnpEventNotifyHandler = 0;
    m_ptrAdapterShutdownHandler = 0;

    // Initialize mini-driver start and end address
    m_drvstartaddr = 0;
    m_drvendaddr = 0;

    // Initialize heap to store minidriver's name
    m_drivername = (PWSTR)malloc(MAX_MINIDRV_NAME*sizeof(WCHAR));

}

// CMinidriver destructor
CMinidriver::~CMinidriver()
{
    free(m_drivername);
}

PWSTR WINAPI CMinidriver::GetMDriverName()
{
    ExtRemoteTyped miniDrv("(ndis!_NDIS_M_DRIVER_BLOCK*)@$extin", m_minidrvaddr);

    // NDIS6.X
    if (utils::IsVistaOrAbove())
    {
        WCHAR wDriverName[MAX_MINIDRV_NAME*sizeof(WCHAR)] = { 0 };
        ExtRemoteTyped minidrvName("(nt!_UNICODE_STRING*)@$extin", miniDrv.Field("ServiceName").m_Offset);
        utils::getUnicodeString(minidrvName, wDriverName, MAX_MINIDRV_NAME*sizeof(WCHAR));

        // ServiceName field might be empty
        // Get minidriver name from DriverObject->DriverName
        if (wcslen(wDriverName) == 0)
        {

            ULONG64 ptrMiniDrvObject = miniDrv.Field("DriverObject").GetPtr();
            ExtRemoteTyped miniDrvObject("(nt!_DRIVER_OBJECT*)@$extin", ptrMiniDrvObject);

            // Get minidriver name (eg: "\Driver\NdisWan")
            ExtRemoteTyped minidrvName2("(nt!_UNICODE_STRING*)@$extin", miniDrvObject.Field("DriverName").m_Offset);
            utils::getUnicodeString(minidrvName2, wDriverName, MAX_MINIDRV_NAME*sizeof(WCHAR));
        }

        // Get minidriver name
        PWSTR drvName = wcsrchr(wDriverName, L'\\');

        if (drvName != NULL)
        {
            StringCchCopyW(m_drivername, MAX_MINIDRV_NAME, drvName + 1);
        }
        else
        {
            StringCchCopyW(m_drivername, MAX_MINIDRV_NAME, wDriverName);
        }
    }
    // NDIS5.X
    else
    {
        ExtRemoteTyped minidrvInfo("(ndis!_NDIS_WRAPPER_HANDLE*)@$extin", miniDrv.Field("NdisDriverInfo").GetPtr());
        ExtRemoteTyped minidrvName("(nt!_UNICODE_STRING*)@$extin", minidrvInfo.Field("ServiceRegPath").m_Offset);

        // Get service registry path
        WCHAR wRegPath[MAX_MINIDRV_NAME*sizeof(WCHAR)] = { 0 };
        utils::getUnicodeString(minidrvName, wRegPath, MAX_MINIDRV_NAME*sizeof(WCHAR));

        // Get minidriver name
        PWSTR drvName = wcsrchr(wRegPath, L'\\');

        if (drvName != NULL)
        {
            StringCchCopyW(m_drivername, MAX_MINIDRV_NAME, drvName + 1);
        }
        else
        {
            StringCchCopyW(m_drivername, MAX_MINIDRV_NAME, wRegPath);
        }

    }

    return m_drivername;
}

BOOL WINAPI CMinidriver::IsHandlerHooked(ULONG64 PtrHandler)
{
    BOOL boolIsHooked = (PtrHandler < m_drvstartaddr) && (m_drvendaddr > PtrHandler);

    if (boolIsHooked)
        return true;
    else
        return false;
}

ULONG64 WINAPI CMinidriver::GetDriverStartAddr()
{
    ExtRemoteTyped miniDrv("(ndis!_NDIS_M_DRIVER_BLOCK*)@$extin", m_minidrvaddr);
    BOOLEAN Is64Bit = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? TRUE : FALSE;
    ExtRemoteTyped drvObj;

    // NDIS6.X
    if (utils::IsVistaOrAbove())
    {
        drvObj = ExtRemoteTyped("(nt!_DRIVER_OBJECT*)@$extin", miniDrv.Field("DriverObject").GetPtr());
    }
    // NDIS5.X
    else
    {
        ExtRemoteTyped minidrvInfo("(ndis!_NDIS_WRAPPER_HANDLE*)@$extin", miniDrv.Field("NdisDriverInfo").GetPtr());
        drvObj = ExtRemoteTyped("(nt!_DRIVER_OBJECT*)@$extin", minidrvInfo.Field("DriverObject").GetPtr());
    }

    m_drvstartaddr = Is64Bit ? drvObj.Field("DriverStart").GetUlong64() : drvObj.Field("DriverStart").GetUlong();
    return m_drvstartaddr;
}

ULONG64 WINAPI CMinidriver::GetDriverEndAddr()
{
    return (m_drvendaddr = utils::getModuleSize(m_drvstartaddr) + m_drvstartaddr);
}

std::map<PCSTR, ULONG64>* WINAPI CMinidriver::GetFunctionHandlers(std::map<PCSTR, ULONG64> *PtrHandlers)
{
    PtrHandlers->insert(std::make_pair("CheckForHangHandler", m_ptrCheckForHangHandler));
    PtrHandlers->insert(std::make_pair("DisableInterruptHandler", m_ptrDisableInterruptHandler));
    PtrHandlers->insert(std::make_pair("EnableInterruptHandler", m_ptrEnableInterruptHandler));
    PtrHandlers->insert(std::make_pair("HaltHandler", m_ptrHaltHandler));
    PtrHandlers->insert(std::make_pair("HandleInterruptHandler", m_ptrHandleInterruptHandler));
    PtrHandlers->insert(std::make_pair("InitializeHandler", m_ptrInitializeHandler));
    PtrHandlers->insert(std::make_pair("ISRHandler", m_ptrIsrHandler));
    PtrHandlers->insert(std::make_pair("QueryInformationHandler", m_ptrQueryInformationHandler));
    PtrHandlers->insert(std::make_pair("ReconfigureHandler", m_ptrReconfigureHandler));
    PtrHandlers->insert(std::make_pair("ResetHandler", m_ptrResetHandler));
    PtrHandlers->insert(std::make_pair("SendHandler", m_ptrSendHandler));
    PtrHandlers->insert(std::make_pair("WanSendHandler", m_ptrWanSendHandler));
    PtrHandlers->insert(std::make_pair("SetInformationHandler", m_ptrSetInformationHandler));
    PtrHandlers->insert(std::make_pair("TransferDataHandler", m_ptrTransferDataHandler));
    PtrHandlers->insert(std::make_pair("WanTransferDataHandler", m_ptrWanTransferDataHandler));
    PtrHandlers->insert(std::make_pair("ReturnPacketHandler", m_ptrReturnPacketHandler));
    PtrHandlers->insert(std::make_pair("SendPacketsHandler", m_ptrSendPacketsHandler));
    PtrHandlers->insert(std::make_pair("AllocateCompleteHandler", m_ptrAllocateCompleteHandler));
    PtrHandlers->insert(std::make_pair("CancelSendPacketsHandler", m_ptrCancelSendPacketsHandler));
    PtrHandlers->insert(std::make_pair("PnpEventNotifyHandler", m_ptrPnpEventNotifyHandler));
    PtrHandlers->insert(std::make_pair("AdapterShutdownHandler", m_ptrAdapterShutdownHandler));

    return PtrHandlers;
}