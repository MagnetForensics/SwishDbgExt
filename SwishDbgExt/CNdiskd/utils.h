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
#pragma once
#include "../engextcpp.hpp"

namespace utils {

ULONG64 findModuleBase(PCSTR);
ULONG64 findModuleBase(PWSTR);
ULONG64 findModuleBase(ULONG64);
ULONG64 getNdisFieldData(ULONG64, ExtRemoteTyped, PSTR);
ULONG64 getPointerFromAddress(ULONG64, PULONG);
ULONG getUlongFromAddress(ULONG64, PULONG);
ULONG getModuleSize(ULONG64);
BOOL IsVistaOrAbove();
PSTR getNameByOffset(ULONG64, PSTR);
PSTR getModuleNameByOffset(ULONG64, PSTR);
PWSTR getUnicodeString(ExtRemoteTyped, PWSTR, ULONG);

}