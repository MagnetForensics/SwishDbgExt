/*++
    Incident Response & Digital Forensics Debugging Extension

    Copyright (C) 2014 MoonSols Ltd.
    Copyright (C) 2016 Comae Technologies FZE
    Copyright (C) 2014-2016 Matthieu Suiche (@msuiche)

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
#include "SwishDbgExt.h"
#include <yara.h>


INT
YaraCallback(
    _In_ INT Message,
    _In_ PVOID MessageData,
    _In_ PVOID UserData
    )
{
    YR_RULE *Rule;
    YR_STRING *String;
    YR_MATCH *Match;
    ULONG64 BaseAddress;

    switch (Message) {

    case CALLBACK_MSG_RULE_MATCHING:
    {
        Rule = (YR_RULE *)MessageData;

        BaseAddress = *(PULONG64)UserData;

        g_Ext->Dml("<col fg=\"changed\">Rule:</col> %s\n\n", Rule->identifier);

        yr_rule_strings_foreach(Rule, String) {

            yr_string_matches_foreach(String, Match) {

                g_Ext->Execute("db %p", BaseAddress + Match->offset);
                g_Ext->Dml("\n");
            }
        }

        break;
    }
    }

    return CALLBACK_CONTINUE;
}

VOID
YaraScan(
    _In_ MsProcessObject *ProcObj,
    _In_ PCSTR FileName
    )
{
    YR_COMPILER *Compiler;
    YR_RULES *Rules;
    FILE *File;
    PBYTE Buffer = NULL;
    ULONG64 RangeStart;
    ULONG64 RangeEnd;
    ULONG64 Offset;

    if (yr_initialize() == ERROR_SUCCESS) {

        if (yr_compiler_create(&Compiler) == ERROR_SUCCESS) {

            if (fopen_s(&File, FileName, "r") == ERROR_SUCCESS) {

                if (yr_compiler_add_file(Compiler, File, NULL, NULL) == 0) {

                    if (yr_compiler_get_rules(Compiler, &Rules) == ERROR_SUCCESS) {

                        Buffer = (PBYTE)calloc(PAGE_SIZE, sizeof(BYTE));

                        if (Buffer) {

                            ProcObj->MmGetVads();

                            ProcObj->SwitchContext();

                            for each (VAD_OBJECT Vad in ProcObj->m_Vads) {

                                //
                                // Check if VAD's range is valid.
                                //

                                if ((Vad.StartingVpn & ~0xFFFFFFFFFF) || (Vad.EndingVpn & ~0xFFFFFFFFFF)) {

                                    continue;
                                }

                                RangeStart = Vad.StartingVpn * PAGE_SIZE;
                                RangeEnd = Vad.EndingVpn * PAGE_SIZE;

                                for (Offset = RangeStart; Offset < RangeEnd; Offset += PAGE_SIZE) {

                                    if (ExtRemoteTypedEx::ReadVirtual(Offset, Buffer, PAGE_SIZE, NULL) != S_OK) {

                                        continue;
                                    }

                                    yr_rules_scan_mem(Rules, Buffer, PAGE_SIZE, 0, YaraCallback, &Offset, 0);
                                }
                            }

                            ProcObj->RestoreContext();

                            free(Buffer);
                        }
                    }
                }

                fclose(File);
            }

            yr_compiler_destroy(Compiler);
        }

        yr_finalize();
    }
}
