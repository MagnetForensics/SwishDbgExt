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

#include "stdafx.h"
#include "..\SwishDbgExt.h"
#include "CNdiskd.h"

// CNdisKd constructor
CNdiskd::CNdiskd()
{
    // Initialize heap to store Ndis build information
    m_ndiskdBuildDate = (PWSTR)LocalAlloc(LMEM_ZEROINIT, MAX_PROTOCOL_NAME*sizeof(WCHAR));
    m_ndiskdBuildTime = (PWSTR)LocalAlloc(LMEM_ZEROINIT, MAX_PROTOCOL_NAME*sizeof(WCHAR));
    m_ndiskdBuiltBy = (PWSTR)LocalAlloc(LMEM_ZEROINIT, MAX_PROTOCOL_NAME*sizeof(WCHAR));
}

// CNdiskd destructor
CNdiskd::~CNdiskd()
{
    // Cleanup
    LocalFree(m_ndiskdBuildDate);
    LocalFree(m_ndiskdBuildTime);
    LocalFree(m_ndiskdBuiltBy);
}

BOOL WINAPI CNdiskd::IsWhitelistedNdisModule(CHAR *moduleName)
{
    if (strstr(moduleName, "ndi") == NULL && strstr(moduleName, "tcp") == NULL &&
        strstr(moduleName, "npf") == NULL && strstr(moduleName, "ndp") == NULL &&
        strstr(moduleName, "wan") == NULL && strstr(moduleName, "psc") == NULL &&
        strstr(moduleName, "ras") == NULL && strstr(moduleName, "vmx") == NULL &&		/* Vmxnet driver name */
        strstr(moduleName, "xxx") == NULL && strstr(moduleName, "asy") == NULL &&		/* Asyncmac miniport driver */
        strstr(moduleName, "agi") == NULL && strstr(moduleName, "e1g") == NULL &&
        strstr(moduleName, "tun") == NULL && strstr(moduleName, "rsp") == NULL &&
        strstr(moduleName, "llt") == NULL &&
        strstr(moduleName, "neo_003") == NULL && /* VPNGate miniport driver */
        strstr(moduleName, "vmnetad") == NULL && /* VMnetAdapter miniport driver */
        strstr(moduleName, "e1c62x6") == NULL && /* E1cexpress miniport driver */
        strstr(moduleName, "vmnetbr") == NULL)   /* VMNet bridge miniport driver */
        return false;
    else
        return true;
}

BOOL WINAPI CNdiskd::IsNdisHook(ULONG64 PtrHandler)
{
    CHAR moduleName[MAX_MODULE_NAME] = { 0 };
    BOOL boolIsHooked, boolWhitelisted = false;

    do
    {
        if (utils::getNameByOffset(PtrHandler, moduleName) == NULL)
            break;

        if (strlen(moduleName) > 0)
        {
            // Convert to lower case
            _strlwr_s(moduleName, sizeof(moduleName));
#if VVERBOSE_MODE
            DbgPrint("DEBUG: %s:%d:%s Checking integrity of module name \"%s\"\n", __FILE__, __LINE__, __FUNCTION__, moduleName);
#endif
            // Check white-listed NDIS module name
            if (CNdiskd::IsWhitelistedNdisModule(moduleName))
            {
                boolWhitelisted = true;
            }
            else
            {
                DbgPrint("DEBUG: %s:%d:%s Module name %s is not whitelisted!\n", __FILE__, __LINE__, __FUNCTION__, moduleName);
            }
        }
    } while (false);

    if (boolWhitelisted)
        boolIsHooked = false;
    else
        boolIsHooked = (PtrHandler < m_ndisBaseAddress) && (m_ndisEndAddress > PtrHandler);

#if VVERBOSE_MODE
    DbgPrint("DEBUG: %s:%d:%s %#I64x vs (%#I64x-%#I64x)\n", __FILE__, __LINE__, __FUNCTION__, PtrHandler, m_ndisBaseAddress, m_ndisEndAddress);
#endif

    if (boolIsHooked)
        return true;
    else
        return false;
}

BOOL WINAPI CNdiskd::HeuristicHookCheck(ULONG64 PtrHandler, int &RuleNo)
{
    BOOL boolIsHooked = false;

    RuleNo = 0;

    do
    {
        //
        // #1 heuristic hook check
        // The handler belong to unamed module
        //
        CHAR moduleName[MAX_MODULE_NAME] = { 0 };

        if (utils::getNameByOffset(PtrHandler, moduleName) == NULL)
        {
            boolIsHooked = true;
            RuleNo = 1;
            break;
        }

        // Convert to lower case
        _strlwr_s(moduleName, sizeof(moduleName));

        if (strlen(moduleName) == 0)
        {
            boolIsHooked = true;
            RuleNo = 1;
            break;
        }

        //
        // #2 heuristic hook check
        // The handler belong to non-whitelisted modules
        //
        if (!CNdiskd::IsWhitelistedNdisModule(moduleName))
        {
            DbgPrint("DEBUG: %s:%d:%s Module name %s is not whitelisted!\n", __FILE__, __LINE__, __FUNCTION__, moduleName);
            boolIsHooked = true;
            RuleNo = 2;
            break;
        }

        //
        // #3 heuristic hook check
        // The prolog of the handler function start with "jmp" instruction
        //
        HRESULT     hres;
        CHAR        buffer[0x100];
        ULONG       disasmSize = 0;
        ULONG64     nextOffset = 0;

        hres =
            g_Ext->m_Control->Disassemble(
            PtrHandler,
            DEBUG_DISASM_EFFECTIVE_ADDRESS,
            buffer,
            sizeof(buffer),
            &disasmSize,
            &nextOffset);

        if (FAILED(hres))
        {
            g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, __FUNCTION__ " : IDebugControl::Disassemble failed\n");
        }
        else
        {
            if (strstr(buffer, "jmp") != NULL)
            {
                boolIsHooked = true;
                RuleNo = 3;
                break;
            }
        }

    } while (false);

    if (boolIsHooked)
        return true;
    else
        return false;
}

CHAR* WINAPI CNdiskd::GetHookType(int RuleNo)
{
    switch (RuleNo)
    {
    case 0:
        return "\"Function handler hijacking\"";
    case 1:
        return "\"Unnamed NDIS module\"";
    case 2:
        return "\"Non-whitelisted NDIS module\"";
    case 3:
        return "\"Function handler detour\"";
    default:
        return "\"\"";
    }
}

//////////////////////////////////////////////////////////////////////////
/*
    Get protocol list:
    *Protocol*<--->Binder<--->Adapter
    */
//////////////////////////////////////////////////////////////////////////
std::list<CProtocols*>* WINAPI
CNdiskd::GetProtocolList(std::list<CProtocols*> *protocolList)
{
    ULONG cbBytesReturned;
    ULONG64 Address;

    // Start parsing ndisProtocolList
    Address = GetExpression("ndis!ndisProtocolList");

    if (Address)
    {
        // Obtain the first protocol from the list
        cbBytesReturned = 0;
        Address = utils::getPointerFromAddress(Address, &cbBytesReturned);

        if (cbBytesReturned > 0)
        {

            DbgPrint("DEBUG: %s:%d:%s Ptr to first protocol (NDIS_PROTOCOL_BLOCK) in the list: %p\n", __FILE__, __LINE__, __FUNCTION__, Address);
            ExtRemoteTyped ndisProtocolList("(ndis!_NDIS_PROTOCOL_BLOCK*)@$extin", Address);

            // Enumerating all protocols, starting from first protocol
            do{
                CProtocols *protocol = new CProtocols();
                ULONG64 addrName = utils::getNdisFieldData(Address, ndisProtocolList, "Name");
                ULONG64 addrNextProtocol = utils::getNdisFieldData(Address, ndisProtocolList, "NextProtocol");

                // Set protocol's information
                ExtRemoteTyped protocolName("(nt!_UNICODE_STRING*)@$extin", addrName);

                // Get current protocol name's heap
                PWSTR Name = protocol->GetProtocolName();

                // Save protocol name
                utils::getUnicodeString(protocolName, Name, MAX_PROTOCOL_NAME*sizeof(WCHAR));
                protocol->SetProtocolName(Name);

                // Save protocol version
                protocol->m_majorversion = (UCHAR)utils::getNdisFieldData(0, ndisProtocolList, "MajorNdisVersion");
                protocol->m_minorversion = (UCHAR)utils::getNdisFieldData(0, ndisProtocolList, "MinorNdisVersion");

                // Save handler functions
                protocol->m_ptrReceiveHandler = utils::getNdisFieldData(0, ndisProtocolList, "ReceiveHandler");
                protocol->m_ptrReceivePacketHandler = utils::getNdisFieldData(0, ndisProtocolList, "ReceivePacketHandler");
                protocol->m_ptrReceiveCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "ReceiveCompleteHandler");
                protocol->m_ptrWanReceiveHandler = utils::getNdisFieldData(0, ndisProtocolList, "WanReceiveHandler");
                protocol->m_ptrResetCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "ResetCompleteHandler");
                protocol->m_ptrWanTransferDataCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "WanTransferDataCompleteHandler");
                protocol->m_ptrTransferDataCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "TransferDataCompleteHandler");
                protocol->m_ptrWanSendCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "WanSendCompleteHandler");
                protocol->m_ptrSendCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "SendCompleteHandler");
                protocol->m_ptrCloseAdapterCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "CloseAdapterCompleteHandler");
                protocol->m_ptrOpenAdapterCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "OpenAdapterCompleteHandler");
                protocol->m_ptrStatusCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "StatusCompleteHandler");
                protocol->m_ptrStatusHandler = utils::getNdisFieldData(0, ndisProtocolList, "StatusHandler");
                protocol->m_ptrRequestCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "RequestCompleteHandler");
                if (utils::IsVistaOrAbove())
                {
                    protocol->m_ptrSendNetBufferListsCompleteHandler = utils::getNdisFieldData(0, ndisProtocolList, "SendNetBufferListsCompleteHandler");
                    protocol->m_ptrReceiveNetBufferListsHandler = utils::getNdisFieldData(0, ndisProtocolList, "ReceiveNetBufferListsHandler");
                    protocol->m_ptrStatusHandlerEx = utils::getNdisFieldData(0, ndisProtocolList, "StatusHandlerEx");
                }

                // Save protocol start and end address
                // Pick a handler that most likely will not be hooked
                ULONG64 Base;
                ULONG64 addrHandler = utils::getNdisFieldData(0, ndisProtocolList, "PnPEventHandler");

                // Sanity check
                if (addrHandler != NULL)
                {
                    protocol->m_protocolStartAddr = Base = utils::findModuleBase(addrHandler);
                    protocol->m_protocolEndAddr = Base + utils::getModuleSize(Base);
                }

                // Get the module name for the protocol's handler
                CHAR moduleName[MAX_MODULE_NAME] = { 0 };
                utils::getNameByOffset(addrHandler, moduleName);

                strcpy_s(protocol->m_ModuleName, MAX_MODULE_NAME, moduleName);

                // For debugging purposes
                DbgPrint("DEBUG: %s:%d:%s Protocol address: %p (%I64x-%I64x [%s]), Protocol name: %msu (v%d.%d)\n",
                    __FILE__, __LINE__, __FUNCTION__, Address, protocol->m_protocolStartAddr, protocol->m_protocolEndAddr,
                    protocol->m_ModuleName, addrName, protocol->m_majorversion, protocol->m_minorversion);
                // Done setting protocol's information, save protocol ptr to vector
                protocolList->push_back(protocol);

                // Next protocol
                Address = utils::getPointerFromAddress(addrNextProtocol, &cbBytesReturned);
                ndisProtocolList = ndisProtocolList.Field("NextProtocol");
            } while (Address != NULL);
        }

    }
    else
    {
        g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, __FUNCTION__ ": Unable to find expression ndisProtocolList\n");
    }

    return protocolList;
}// GetProtocolList

//////////////////////////////////////////////////////////////////////////
/*
    Get adapter list:
    Protocol<--->Binder<--->*Adapter*
    */
//////////////////////////////////////////////////////////////////////////
std::list<CAdapters*>* WINAPI
CNdiskd::GetAdapterList(std::list<CAdapters*> *adapterList)
{
    ULONG cbBytesReturned;
    ULONG64 Address;

    // Start parsing Miniport list
    Address = GetExpression("ndis!ndisMiniportList");

    if (Address)
    {
        // Obtain the first protocol from the list
        cbBytesReturned = 0;
        Address = utils::getPointerFromAddress(Address, &cbBytesReturned);

        if (cbBytesReturned > 0)
        {
            DbgPrint("DEBUG: %s:%d:%s Ptr to first adapter (NDIS_MINIPORT_BLOCK) in the list: %p\n", __FILE__, __LINE__, __FUNCTION__, Address);

            ExtRemoteTyped ndisMiniportList("(ndis!_NDIS_MINIPORT_BLOCK*)@$extin", Address);

            // Enumerating all protocols, starting from first protocol
            do{
                CAdapters *adapter = new CAdapters();
                ULONG64 pAdatperName = ndisMiniportList.Field("pAdapterInstanceName").GetPtr();
                ULONG64 addrNextMiniport = utils::getNdisFieldData(Address, ndisMiniportList, "NextGlobalMiniport");

                // Set adapter's information
                ExtRemoteTyped apdaterName("(nt!_UNICODE_STRING*)@$extin", pAdatperName);

                // Get current adapter name's heap
                PWSTR Name = adapter->GetAdapterName();

                // Save adapter name
                utils::getUnicodeString(apdaterName, Name, MAX_ADAPTER_NAME*sizeof(WCHAR));
                adapter->SetAdapterName(Name);

                // Save handler functions
                adapter->m_ptrPacketIndicateHandler = utils::getNdisFieldData(0, ndisMiniportList, "PacketIndicateHandler");
                adapter->m_ptrResetCompleteHandler = utils::getNdisFieldData(0, ndisMiniportList, "ResetCompleteHandler");
                adapter->m_ptrWanSendCompleteHandler = utils::getNdisFieldData(0, ndisMiniportList, "WanSendCompleteHandler");
                adapter->m_ptrSendCompleteHandler = utils::getNdisFieldData(0, ndisMiniportList, "SendCompleteHandler");
                adapter->m_ptrWanRcvHandler = utils::getNdisFieldData(0, ndisMiniportList, "WanRcvHandler");
                adapter->m_ptrWanRcvCompleteHandler = utils::getNdisFieldData(0, ndisMiniportList, "WanRcvCompleteHandler");
                adapter->m_ptrStatusCompleteHandler = utils::getNdisFieldData(0, ndisMiniportList, "StatusCompleteHandler");
                adapter->m_ptrStatusHandler = utils::getNdisFieldData(0, ndisMiniportList, "StatusHandler");

                if (utils::IsVistaOrAbove())
                {
                    adapter->m_ptrSendNetBufferListsCompleteHandler = utils::getNdisFieldData(0, ndisMiniportList, "SendNetBufferListsCompleteHandler");
                }

                // Save adapter start and end address
                // Pick a handler that most likely will not be hooked
                ULONG64 Base;
                ULONG64 addrHandler = utils::getNdisFieldData(0, ndisMiniportList, "SendResourcesHandler");

                // Sanity check
                if (addrHandler != NULL)
                {
                    adapter->m_ndisStartAddr = Base = utils::findModuleBase(addrHandler);
                    adapter->m_ndisEndAddr = Base + utils::getModuleSize(Base);
                }

                // For debugging purposes
                DbgPrint("DEBUG: %s:%d:%s Adapter address: %p, Adapter name: %msu\n", __FILE__, __LINE__, __FUNCTION__, Address, pAdatperName);

                // Done setting protocol's information, save protocol ptr to vector
                adapterList->push_back(adapter);

                // Next protocol
                Address = utils::getPointerFromAddress(addrNextMiniport, &cbBytesReturned);
                ndisMiniportList = ndisMiniportList.Field("NextGlobalMiniport");
            } while (Address != NULL);
        }

    }
    else
    {
        g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, __FUNCTION__ ": Unable to find expression ndisMiniportList\n");
    }

    return adapterList;
}// GetAdapterList

//////////////////////////////////////////////////////////////////////////
/*
    Get open binder list:
    Protocol<--->*Binder*<--->Adapter
    */
//////////////////////////////////////////////////////////////////////////
std::list<COpenblock*>* WINAPI
CNdiskd::GetOpenblockList(std::list<COpenblock*> *openblockList)
{
    ULONG cbBytesReturned;
    ULONG64 Address;

    // Start parsing open block list
    Address = GetExpression("ndis!ndisGlobalOpenList");

    if (Address)
    {
        // Obtain the first open block from the list
        cbBytesReturned = 0;
        Address = utils::getPointerFromAddress(Address, &cbBytesReturned);

        if (cbBytesReturned > 0)
        {
            DbgPrint("DEBUG: %s:%d:%s Ptr to first adapter (NDIS_OPEN_BLOCK) in the list: %p\n", __FILE__, __LINE__, __FUNCTION__, Address);

            ExtRemoteTyped ndisOpenblockList("(ndis!_NDIS_OPEN_BLOCK*)@$extin", Address);

            // Enumerating all binders, starting from first binder
            do{
                COpenblock *binder = new COpenblock(Address);
                ULONG64 addrName = ndisOpenblockList.Field("BindDeviceName").GetPtr();
                ULONG64 addrNextOpenBlock = utils::getNdisFieldData(Address, ndisOpenblockList, "NextGlobalOpen");

                // Set binder's information
                ExtRemoteTyped usbinderName("(nt!_UNICODE_STRING*)@$extin", addrName);

                // Get current binder name's heap
                PWSTR Name = binder->GetBinderName();

                // Save binder name
                utils::getUnicodeString(usbinderName, Name, MAX_BINDING_NAME*sizeof(WCHAR));
                binder->SetBinderName(Name);

                // Get protocol associated with the binder
                PWSTR protName = binder->GetProtocolName();

                // Get adapter associated with the binder
                PWSTR adaptName = binder->GetAdpaterName();

                // Save handler functions
                binder->m_ptrSendHandler = utils::getNdisFieldData(0, ndisOpenblockList, "SendHandler");
                binder->m_ptrResetCompleteHandler = utils::getNdisFieldData(0, ndisOpenblockList, "ResetCompleteHandler");
                binder->m_ptrSendCompleteHandler = utils::getNdisFieldData(0, ndisOpenblockList, "SendCompleteHandler");
                binder->m_ptrSendPacketsHandler = utils::getNdisFieldData(0, ndisOpenblockList, "SendPacketsHandler");
                binder->m_ptrReceiveHandler = utils::getNdisFieldData(0, ndisOpenblockList, "ReceiveHandler");
                binder->m_ptrReceiveCompleteHandler = utils::getNdisFieldData(0, ndisOpenblockList, "ReceiveCompleteHandler");
                binder->m_ptrWanReceiveHandler = utils::getNdisFieldData(0, ndisOpenblockList, "WanReceiveHandler");
                binder->m_ptrRequestCompleteHandler = utils::getNdisFieldData(0, ndisOpenblockList, "RequestCompleteHandler");
                binder->m_ptrReceivePacketHandler = utils::getNdisFieldData(0, ndisOpenblockList, "ReceivePacketHandler");
                binder->m_ptrWanSendHandler = utils::getNdisFieldData(0, ndisOpenblockList, "WanSendHandler");
                binder->m_ptrStatusCompleteHandler = utils::getNdisFieldData(0, ndisOpenblockList, "StatusCompleteHandler");
                binder->m_ptrStatusHandler = utils::getNdisFieldData(0, ndisOpenblockList, "StatusHandler");

                if (utils::IsVistaOrAbove())
                {
                    binder->m_ptrReceiveNetBufferLists = utils::getNdisFieldData(0, ndisOpenblockList, "ReceiveNetBufferLists");
                }

                // Save NDIS module start and end address that will be later used to check if the 
                // function handlers have been hooked
                binder->m_ndisStartAddr = m_ndisBaseAddress;
                binder->m_ndisEndAddr = m_ndisEndAddress;

                // Save bounding protocol module start and end address
                // Pick a handler that most likely will not be hooked
                ULONG64 Base;
                ULONG64 addrHandler = utils::getNdisFieldData(0, ndisOpenblockList.Field("ProtocolHandle"), "PnPEventHandler");

                // Sanity check
                if (addrHandler != NULL)
                {
                    binder->m_bindProtocolHandlerStartAddr = Base = utils::findModuleBase(addrHandler);
                    binder->m_bindProtocolHandlerEndAddr = Base + utils::getModuleSize(Base);
                }

                // Save bounding adapter module start and end address
                binder->m_bindAdapterHandlerStartAddr = binder->GetMiniDriverStartAddr();
                binder->m_bindAdapterHandlerEndAddr = binder->GetMiniDriverEndAddr();

                // For debugging purposes
                DbgPrint("DEBUG: %s:%d:%s Binder address: %p, Protocol: %ls<-->Binder: %msu<-->Adapter: %ls\n", __FILE__, __LINE__, __FUNCTION__, Address, protName, addrName, adaptName);

                // Done setting binder's information, save binder's ptr to vector
                openblockList->push_back(binder);

                // Next binder
                Address = utils::getPointerFromAddress(addrNextOpenBlock, &cbBytesReturned);
                ndisOpenblockList = ndisOpenblockList.Field("NextGlobalOpen");
            } while (Address != NULL);
        }

    }
    else
    {
        g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, __FUNCTION__ ": Unable to find expression ndisGlobalOpenList\n");
    }

    return openblockList;
}// GetOpenblockList

std::list<CMinidriver*>* WINAPI
CNdiskd::GetMDriverList(std::list<CMinidriver*> *mDrvList)
{
    ULONG cbBytesReturned;
    ULONG64 Address;

    // Start parsing Miniport list
    Address = GetExpression("ndis!ndisMinidriverList");

    if (Address)
    {
        // Obtain the first protocol from the list
        cbBytesReturned = 0;
        Address = utils::getPointerFromAddress(Address, &cbBytesReturned);

        if (cbBytesReturned > 0)
        {
            DbgPrint("DEBUG: %s:%d:%s Ptr to first minidriver (NDIS_M_DRIVER_BLOCK) in the list: %p\n", __FILE__, __LINE__, __FUNCTION__, Address);

            ExtRemoteTyped ndisMiniDrvList("(ndis!_NDIS_M_DRIVER_BLOCK*)@$extin", Address);

            // Enumerating all mini-drivers, starting from first mini-driver
            do{
                CMinidriver *minidriver = new CMinidriver(Address);
                ULONG64 addrNextMDrv = utils::getNdisFieldData(Address, ndisMiniDrvList, "NextDriver");

                // Save handler functions
                minidriver->m_ptrCheckForHangHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.CheckForHangHandler");
                minidriver->m_ptrDisableInterruptHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.DisableInterruptHandler");
                minidriver->m_ptrEnableInterruptHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.EnableInterruptHandler");
                minidriver->m_ptrHaltHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.HaltHandler");
                minidriver->m_ptrHandleInterruptHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.HandleInterruptHandler");
                minidriver->m_ptrInitializeHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.InitializeHandler");
                minidriver->m_ptrIsrHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.ISRHandler");
                minidriver->m_ptrQueryInformationHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.QueryInformationHandler");
                minidriver->m_ptrReconfigureHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.ReconfigureHandler");
                minidriver->m_ptrResetHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.ResetHandler");
                minidriver->m_ptrSendHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.SendHandler");
                minidriver->m_ptrWanSendHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.WanSendHandler");
                minidriver->m_ptrSetInformationHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.SetInformationHandler");
                minidriver->m_ptrTransferDataHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.TransferDataHandler");
                minidriver->m_ptrWanTransferDataHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.WanTransferDataHandler");
                minidriver->m_ptrReturnPacketHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.ReturnPacketHandler");
                minidriver->m_ptrSendPacketsHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.SendPacketsHandler");
                minidriver->m_ptrAllocateCompleteHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.AllocateCompleteHandler");
                minidriver->m_ptrCancelSendPacketsHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.CancelSendPacketsHandler");
                minidriver->m_ptrPnpEventNotifyHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.PnPEventNotifyHandler");
                minidriver->m_ptrAdapterShutdownHandler = utils::getNdisFieldData(0, ndisMiniDrvList, "MiniportCharacteristics.AdapterShutdownHandler");

                // For debugging purposes
                PWSTR MDrvName = minidriver->GetMDriverName();
                DbgPrint("DEBUG: %s:%d:%s Mini-driver address: %p, Mini-driver name: %ls\n", __FILE__, __LINE__, __FUNCTION__, Address, MDrvName);

                // Done setting protocol's information, save protocol ptr to vector
                mDrvList->push_back(minidriver);

                // Next protocol
                Address = utils::getPointerFromAddress(addrNextMDrv, &cbBytesReturned);
                ndisMiniDrvList = ndisMiniDrvList.Field("NextDriver");
            } while (Address != NULL);
        }

    }
    else
    {
        g_Ext->m_Control->Output(DEBUG_OUTPUT_ERROR, __FUNCTION__ ": Unable to find expression ndisMinidriverList\n");
    }

    return mDrvList;
}// GetMDriverList