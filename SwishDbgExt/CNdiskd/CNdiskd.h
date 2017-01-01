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

#ifndef _CNDISKD_H_
#define _CNDISKD_H_

#ifdef _DEBUG
#define DBG 1
#else
#define DBG 0
#endif

#include <windows.h>
#include <intsafe.h>
#include <string.h>
#include <list>
#include <strsafe.h>
#include <map>
#include <vector>
#include <stdio.h>
#include <stdarg.h>
#define KDEXT_64BIT  
#include "CProtocols.h"
#include "CAdapters.h"
#include "COpenblock.h"
#include "CMinidriver.h"
#include "CReport.h"
#include "utils.h"

#define SIGN_EXTEND(_x_) (ULONG64)(LONG)(_x_)
#define NDIS_NAME "ndis"
#define NDIS_DRV_NAME "ndis.sys"

class CNdiskd
{
public:
    CNdiskd();
    ~CNdiskd();
    BOOL WINAPI IsNdisHook(ULONG64);
    BOOL WINAPI HeuristicHookCheck(ULONG64, int&);
    CHAR* WINAPI GetHookType(int);
    ULONG64 m_ndisBaseAddress;
    ULONG64 m_ndisEndAddress;
    ULONG m_ndiskdChecked;
    PWSTR m_ndiskdBuildDate;
    PWSTR m_ndiskdBuildTime;
    PWSTR m_ndiskdBuiltBy;
    std::list<CProtocols*>* WINAPI GetProtocolList(std::list<CProtocols*> *protocolList);
    std::list<CAdapters*>* WINAPI GetAdapterList(std::list<CAdapters*> *adapterList);
    std::list<COpenblock*>* WINAPI GetOpenblockList(std::list<COpenblock*> *openblockList);
    std::list<CMinidriver*>* WINAPI GetMDriverList(std::list<CMinidriver*> *mDrvList);
private:
    BOOL WINAPI IsWhitelistedNdisModule(CHAR*);
};

#endif