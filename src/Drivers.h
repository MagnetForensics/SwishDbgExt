/*++
    MoonSols Incident Response & Digital Forensics Debugging Extension

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

- Driver.h

Abstract:

- ExtRemoteData Pointer(GetExpression("'htsxxxxx!gRingBuffer"), m_PtrSize); // <<< works just fine



Environment:

- User mode

Revision History:

- Matthieu Suiche

--*/

#ifndef __DRIVERS_H__
#define __DRIVERS_H__

class MsDriverObject : public PEFile {
public:
    typedef struct _FAST_IO_DISPATCH
    {
        ULONG64 FastIoCheckIfPossible;
        ULONG64 FastIoRead;
        ULONG64 FastIoWrite;
        ULONG64 FastIoQueryBasicInfo;
        ULONG64 FastIoQueryStandardInfo;
        ULONG64 FastIoLock;
        ULONG64 FastIoUnlockSingle;
        ULONG64 FastIoUnlockAll;
        ULONG64 FastIoUnlockAllByKey;
        ULONG64 FastIoDeviceControl;
        ULONG64 AcquireFileForNtCreateSection;
        ULONG64 ReleaseFileForNtCreateSection;
        ULONG64 FastIoDetachDevice;
        ULONG64 FastIoQueryNetworkOpenInfo;
        ULONG64 AcquireForModWrite;
        ULONG64 MdlRead;
        ULONG64 MdlReadComplete;
        ULONG64 PrepareMdlWrite;
        ULONG64 MdlWriteComplete;
        ULONG64 FastIoReadCompressed;
        ULONG64 FastIoWriteCompressed;
        ULONG64 MdlReadCompleteCompressed;
        ULONG64 MdlWriteCompleteCompressed;
        ULONG64 FastIoQueryOpen;
        ULONG64 ReleaseForModWrite;
        ULONG64 AcquireForCcFlush;
        ULONG64 ReleaseForCcFlush;
    } FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;

    typedef struct _DRIVER_INFO {
        IMAGE_TYPE ImageType; // Always in first position.

        ULONG64 DeviceObject;
        ULONG64 DriverStart;
        ULONG DriverSize;
        ULONG64 DriverSection;
        ULONG64 DriverExtension;

        WCHAR DriverName[MAX_PATH];

        FAST_IO_DISPATCH FastIoDispatch;
        ULONG64 DriverInit;
        ULONG64 DriverStartIo;
        ULONG64 DriverUnload;

        ULONG64 MajorFunction[28];

        ULONG64 LoadTime;
        WCHAR DllName[MAX_PATH + 1];
        WCHAR FullDllName[MAX_PATH + 1];

        FILE_VERSION FileVersion;
    } DRIVER_INFO, *PDRIVER_INFO;

    MsDriverObject()
    {
        Clear();
    }

    MsDriverObject(ULONG64 Object)
    {
        Clear();

        m_TypedObject = ExtRemoteTyped("(nt!_DRIVER_OBJECT *)@$extin", Object);
        Set();
    }

    MsDriverObject(ExtRemoteTyped Object)
    {
        Clear();
        m_TypedObject = Object;
        Set();
    }
    ~MsDriverObject();

    VOID Set();

    BOOLEAN Init(VOID);

    DRIVER_INFO mm_DriverInfo;

    ExtRemoteTyped m_TypedObject;
};

vector<MsDriverObject>
GetDrivers(
);

#endif