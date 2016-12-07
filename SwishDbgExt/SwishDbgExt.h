/*++
    MoonSols Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2014 MoonSols Ltd.
    Copyright (C) 2014 Matthieu Suiche (@msuiche)
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

Module Name:

    - SwishDbgExt.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#define VERBOSE_MODE FALSE
#define VVERBOSE_MODE FALSE
#define JSON_SUPPORT FALSE

#include "json.hpp"

using namespace std;
using json = nlohmann::json;

#if JSON_SUPPORT
#include <json.h>
#include <http_client.h>

using namespace web;
using namespace web::http;
using namespace web::http::client;
#endif

#pragma once
#include "engextcpp.hpp"
#include "EngExpCppEx.h"
#include "UntypedData.h"

#include "NtDef.h"
#include "DbgHelpEx.h"

#include "Credentials.h"
#include "Process.h"
#include "Drivers.h"
#include "Registry.h"
#include "Network.h"
#include "System.h"
#include "Storage.h"
#include "VirusTotal.h"
#include "Checks\Codecave.h"

#include "Security.h"

#include "Objects.h"

#include "Md5.h"

#include "Output.h"

#include "CNdiskd\CNdiskd.h"

#pragma comment(lib, "version.lib")
#if JSON_SUPPORT
#pragma comment(lib, "cpprest120_1_4.lib")
#endif

#define API_EXPORT __declspec(dllexport)
#define SIGN_EXTEND(_x_) (ULONG64)(LONG)(_x_) 
#define PAGE_SIZE 0x1000

#if VERBOSE_MODE
#define ASSERTDBG(exp) if (!(exp)) g_Ext->Dml("ASSERT: %s:%d:%s %s\n", __FILE__, __LINE__, __FUNCTION__, #exp);
#define ASSERT(exp) if (!(exp)) g_Ext->Dml("ASSERT: %s:%d:%s %s\n", __FILE__, __LINE__, __FUNCTION__, #exp);
#else
#define ASSERTDBG(exp) ((void)0)
#define ASSERT(exp) exp;
#endif

#define GetPtrSize() (g_Ext->m_PtrSize)
#define DbgPrint(fmt,...) if (VERBOSE_MODE) g_Ext->Dml(fmt, __VA_ARGS__);

#ifdef __cplusplus
extern "C" {
#endif

//
// Definition
//

extern BOOLEAN g_Verbose;

VOID
ReleaseObjectTypeTable(
    VOID
    );

#ifdef __cplusplus
}
#endif