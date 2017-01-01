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

CReport::CReport(ExtCheckedPointer<ExtExtension> gExt) : m_gExt(gExt)
{
    // Constructor
}

//////////////////////////////////////////////////////////////////////////
// Output hooks report in using Debugger Markup Language
// @Param: None
// @Return: None
//////////////////////////////////////////////////////////////////////////
VOID WINAPI CReport::ReportHooks(PCSTR Format, ...)
{

    CHAR Buffer[1024] = { 0 };
    va_list Args;

    va_start(Args, Format);

    vsnprintf_s(Buffer, _countof(Buffer), _TRUNCATE, Format, Args);

    m_gExt->Dml(Buffer);

    va_end(Args);
}
