/*++
    Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2014 MoonSols Ltd.
    Copyright (C) 2014 Matthieu Suiche (@msuiche)

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

    - VirusTotal.h

Abstract:

    - 

Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef __VIRUSTOTAL_H__
#define __VIRUSTOTAL_H__

#include "SwishDbgExt.h"

#if JSON_SUPPORT
class VirusTotal {
public:
    static pplx::task<void> GetReport(PUCHAR Md5Section);

};
#endif

#endif