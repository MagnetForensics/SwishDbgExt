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


// COpenblock constructor
COpenblock::COpenblock(ULONG64 OpenBlockAddr)
{
	// Initialize binder address
	m_binderAddress = OpenBlockAddr;

	// Initialize NDIS module start and end address
	m_ndisStartAddr = 0;
	m_ndisEndAddr = 0;

	// Initialize the bounding protocol module start and end address
	m_bindProtocolHandlerStartAddr = 0;
	m_bindProtocolHandlerEndAddr = 0;

	// Initialize the bounding adapter module start and end address
	m_bindAdapterHandlerStartAddr = 0;
	m_bindAdapterHandlerEndAddr = 0;

	// Initialize handler function address
	m_ptrSendHandler = 0;
	m_ptrSendCompleteHandler = 0;
	m_ptrSendPacketsHandler = 0;
	m_ptrReceiveHandler = 0;
	m_ptrReceiveCompleteHandler = 0;
	m_ptrResetCompleteHandler = 0;
	m_ptrStatusHandler = 0;
	m_ptrStatusCompleteHandler = 0;
	m_ptrWanReceiveHandler = 0;
	m_ptrRequestCompleteHandler = 0;
	m_ptrReceivePacketHandler = 0;
	m_ptrWanSendHandler = 0;
	m_ptrReceiveNetBufferLists = 0;

	// Initialize heap to store protocol's information
	m_bindingname = (PWSTR)malloc(MAX_BINDING_NAME*sizeof(WCHAR));
	m_protocolname = (PWSTR)malloc(MAX_PROTOCOL_NAME*sizeof(WCHAR));
	m_adaptername = (PWSTR)malloc(MAX_ADAPTER_NAME*sizeof(WCHAR));
}

// COpenblock destructor
COpenblock::~COpenblock()
{
	// Cleanup
	free(m_bindingname);
	free(m_protocolname);
	free(m_adaptername);

}

BOOL WINAPI COpenblock::IsHandlerHooked(ULONG64 PtrHandler)
{
	// If the binder's handler not belong to/within:
	// - Miniport (eg: NDIS) address range
	// - Protocol (eg: NDISWAN or PSCHED [XP]) address range
	/*
		**** NDIS6.X ****
		kd> !ndiskd.mopen

		Open fffffa800271d8d0
		Miniport: fffffa800210a1a0 - Intel(R) PRO/1000 MT Network Connection
		Protocol: fffffa800198d3b0 - TCPIP

		kd> dt _ndis_open_block SendHandler WanSendHandler  ReceiveHandler  ReceivePacketHandler fffffa800271d8d0
		ndis!_NDIS_OPEN_BLOCK
		+0x060 SendHandler          : 0xfffff880`01589cd0     int  ndis!ndisMSend+0
		+0x060 WanSendHandler       : 0xfffff880`01589cd0     int  ndis!ndisMSend+0
		+0x080 ReceiveHandler       : (null) 
		+0x0a0 ReceivePacketHandler : (null) 

		**** NDIS5.X ****
		kd> !ndiskd.mopen

		Open 81a681c0
		Miniport: 8185c378 - VMware Accelerated AMD PCNet Adapter
		Protocol: 81a0a220 - PSCHED

		Open 81a80160
		Miniport: 81a07130 - WAN Miniport (L2TP)
		Protocol: 81a60008 - NDISWAN

		kd> dt _ndis_open_block SendHandler WanSendHandler  ReceiveHandler  ReceivePacketHandler  81a681c0
		NDIS!_NDIS_OPEN_BLOCK
		+0x030 SendHandler          : 0xf96f687b     int  NDIS!ndisMSendX+0
		+0x030 WanSendHandler       : 0xf96f687b     int  NDIS!ndisMSendX+0
		+0x040 ReceiveHandler       : 0xf95dc3bc     int  psched!ClReceiveIndication+0
		+0x050 ReceivePacketHandler : 0xf95dc1c8     int  psched!ClReceivePacket+0
		kd> dt _ndis_open_block SendHandler WanSendHandler  ReceiveHandler  ReceivePacketHandler  81a80160
		NDIS!_NDIS_OPEN_BLOCK
		+0x030 SendHandler          : 0xf96f687b     int  NDIS!ndisMSendX+0
		+0x030 WanSendHandler       : 0xf96f687b     int  NDIS!ndisMSendX+0
		+0x040 ReceiveHandler       : 0xf95f0d4b     int  ndiswan!ProtoWanReceiveIndication+0
		+0x050 ReceivePacketHandler : (null) 

	*/
	BOOL boolIsValid = ((PtrHandler >= m_ndisStartAddr) && (PtrHandler <= m_ndisEndAddr)) || \
						((PtrHandler >= m_bindProtocolHandlerStartAddr) && (PtrHandler <= m_bindProtocolHandlerEndAddr)) || \
						((PtrHandler >= m_bindAdapterHandlerStartAddr) && (PtrHandler <= m_bindAdapterHandlerEndAddr));

	if (!boolIsValid)
		return true;
	else
		return false;
}

ULONG64 WINAPI COpenblock::GetMiniDriverStartAddr()
{
	ExtRemoteTyped openBlock("(ndis!_NDIS_OPEN_BLOCK*)@$extin", m_binderAddress);
	BOOLEAN Is64Bit = (g_Ext->m_Control->IsPointer64Bit() == S_OK) ? TRUE : FALSE;
	ExtRemoteTyped miniportBlock, devObj, drvObj;

	miniportBlock = ExtRemoteTyped("(ndis!_NDIS_MINIPORT_BLOCK*)@$extin", openBlock.Field("MiniportHandle").GetPtr());
	devObj = ExtRemoteTyped("(nt!_DEVICE_OBJECT*)@$extin", miniportBlock.Field("DeviceObject").GetPtr());
	drvObj = ExtRemoteTyped("(nt!_DRIVER_OBJECT*)@$extin", devObj.Field("DriverObject").GetPtr());
	

	m_bindAdapterHandlerStartAddr = Is64Bit?drvObj.Field("DriverStart").GetUlong64():drvObj.Field("DriverStart").GetUlong();
	return m_bindAdapterHandlerStartAddr;
}

ULONG64 WINAPI COpenblock::GetMiniDriverEndAddr()
{
	return (m_bindAdapterHandlerEndAddr = utils::getModuleSize(m_bindAdapterHandlerStartAddr) + m_bindAdapterHandlerStartAddr);
}

VOID WINAPI COpenblock::SetBinderName(PWSTR AdatperName)
{
	wcscpy_s(m_bindingname, MAX_BINDING_NAME, AdatperName);
}

PWSTR WINAPI COpenblock::GetBinderName()
{
	return m_bindingname;
}

PWSTR  WINAPI COpenblock::GetProtocolName()
{
	ExtRemoteTyped openBlock("(ndis!_NDIS_OPEN_BLOCK*)@$extin", m_binderAddress);
	ExtRemoteTyped protBlock("(ndis!_NDIS_PROTOCOL_BLOCK*)@$extin", openBlock.Field("ProtocolHandle").GetPtr());
	ExtRemoteTyped protName("(nt!_UNICODE_STRING*)@$extin", utils::getNdisFieldData(openBlock.Field("ProtocolHandle").GetPtr(), protBlock, "Name"));
	// Get protocol name in m_protocolName
	utils::getUnicodeString(protName, m_protocolname, MAX_PROTOCOL_NAME*sizeof(WCHAR)); 

	return m_protocolname;
}

PWSTR  WINAPI COpenblock::GetAdpaterName()
{
	ExtRemoteTyped openBlock("(ndis!_NDIS_OPEN_BLOCK*)@$extin", m_binderAddress);
	ExtRemoteTyped miniBlock("(ndis!_NDIS_MINIPORT_BLOCK*)@$extin", openBlock.Field("MiniportHandle").GetPtr());
	ExtRemoteTyped adapterName("(nt!_UNICODE_STRING*)@$extin", miniBlock.Field("pAdapterInstanceName").GetPtr());
	// Get adapter name in m_adaptername
	utils::getUnicodeString(adapterName, m_adaptername, MAX_ADAPTER_NAME*sizeof(WCHAR)); 

	return m_adaptername;
}

std::map<PCSTR, ULONG64>* WINAPI COpenblock::GetFunctionHandlers(std::map<PCSTR, ULONG64> *PtrHandlers)
{
	PtrHandlers->insert(std::make_pair("SendHandler", m_ptrSendHandler));
	PtrHandlers->insert(std::make_pair("SendCompleteHandler", m_ptrSendCompleteHandler));
	PtrHandlers->insert(std::make_pair("ResetCompleteHandler", m_ptrResetCompleteHandler));
	PtrHandlers->insert(std::make_pair("SendPacketsHandler", m_ptrSendPacketsHandler));
	PtrHandlers->insert(std::make_pair("ReceiveHandler", m_ptrReceiveHandler));
	PtrHandlers->insert(std::make_pair("ReceiveCompleteHandler", m_ptrReceiveCompleteHandler));
	PtrHandlers->insert(std::make_pair("WanReceiveHandler", m_ptrWanReceiveHandler));
	PtrHandlers->insert(std::make_pair("RequestCompleteHandler", m_ptrRequestCompleteHandler));
	PtrHandlers->insert(std::make_pair("ReceivePacketHandler", m_ptrReceivePacketHandler));
	PtrHandlers->insert(std::make_pair("StatusCompleteHandler", m_ptrStatusCompleteHandler));
	PtrHandlers->insert(std::make_pair("StatusHandler", m_ptrStatusHandler));
	PtrHandlers->insert(std::make_pair("WanSendHandler", m_ptrWanSendHandler));
	PtrHandlers->insert(std::make_pair("ReceiveNetBufferLists", m_ptrReceiveNetBufferLists));

	return PtrHandlers;
}