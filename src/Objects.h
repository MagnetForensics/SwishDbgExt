/*++
MoonSols Incident Response & Digital Forensics Debugging Extension
Copyright (C) 2014 MoonSols Ltd. All rights reserved.

Module Name:

- Objects.h

Abstract:

- ExtRemoteData Pointer(GetExpression("'htsxxxxx!gRingBuffer"), m_PtrSize); // <<< works just fine



Environment:

- User mode

Revision History:

- Matthieu Suiche

--*/

#ifndef __OBJECTS_H__
#define __OBJECTS_H__

BOOLEAN
ObReadObject(
    IN ULONG64 Object,
    OUT PHANDLE_OBJECT HandleObj
);

vector<HANDLE_OBJECT>
ObOpenObjectDirectory(
    IN ULONG64 ObjectDir
);

BOOLEAN
ObOpenChildren(
    OPTIONAL IN ULONG64 Root,
    IN LPWSTR ObjName,
    OUT PHANDLE_OBJECT OutHandle
);

ULONG64
ObGetDriverObject(
);

#endif