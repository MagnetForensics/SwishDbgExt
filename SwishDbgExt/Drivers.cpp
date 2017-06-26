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

    - Ob.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche
--*/

#include "stdafx.h"
#include "SwishDbgExt.h"

VOID
MsDriverObject::Set(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    None.

--*/
{
    ULONG64 MajorFunction[_countof(mm_DriverInfo.MajorFunction)];

    try {

        m_ObjectPtr = m_TypedObject.GetPtr();

        mm_DriverInfo.DeviceObject = m_TypedObject.Field("DeviceObject").GetPtr();
        mm_DriverInfo.DriverStart = m_TypedObject.Field("DriverStart").GetPtr();
        mm_DriverInfo.DriverSize = m_TypedObject.Field("DriverSize").GetUlong();
        mm_DriverInfo.DriverSection = m_TypedObject.Field("DriverSection").GetPtr();
        mm_DriverInfo.DriverExtension = m_TypedObject.Field("DriverExtension").GetPtr();
        mm_DriverInfo.DriverInit = m_TypedObject.Field("DriverInit").GetPtr();
        mm_DriverInfo.DriverStartIo = m_TypedObject.Field("DriverStartIo").GetPtr();
        mm_DriverInfo.DriverUnload = m_TypedObject.Field("DriverUnload").GetPtr();

        ExtRemoteTypedEx::GetUnicodeString(m_TypedObject.Field("DriverName"), (PWSTR)&mm_DriverInfo.DriverName, sizeof(mm_DriverInfo.DriverName));

        if (mm_DriverInfo.DriverSection) {

            ExtRemoteTyped LdrData("(nt!_LDR_DATA_TABLE_ENTRY *)@$extin", mm_DriverInfo.DriverSection);

            ExtRemoteTypedEx::GetUnicodeString(LdrData.Field("FullDllName"), (PWSTR)&mm_DriverInfo.FullDllName, sizeof(mm_DriverInfo.FullDllName));
            ExtRemoteTypedEx::GetUnicodeString(LdrData.Field("BaseDllName"), (PWSTR)&mm_DriverInfo.DllName, sizeof(mm_DriverInfo.DllName));

            m_ImageBase = LdrData.Field("DllBase").GetPtr();
            m_ImageSize = LdrData.Field("SizeOfImage").GetUlong();
        }

        if (m_TypedObject.Field("FastIoDispatch").GetPtr()) {

            ExtRemoteTyped FastIoDispatch = m_TypedObject.Field("FastIoDispatch");

            GetAddressInfo(FastIoDispatch.Field("FastIoCheckIfPossible").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoCheckIfPossible);
            GetAddressInfo(FastIoDispatch.Field("FastIoRead").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoRead);
            GetAddressInfo(FastIoDispatch.Field("FastIoWrite").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoWrite);
            GetAddressInfo(FastIoDispatch.Field("FastIoQueryBasicInfo").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoQueryBasicInfo);
            GetAddressInfo(FastIoDispatch.Field("FastIoQueryStandardInfo").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoQueryStandardInfo);
            GetAddressInfo(FastIoDispatch.Field("FastIoLock").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoLock);
            GetAddressInfo(FastIoDispatch.Field("FastIoUnlockSingle").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoUnlockSingle);
            GetAddressInfo(FastIoDispatch.Field("FastIoUnlockAll").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoUnlockAll);
            GetAddressInfo(FastIoDispatch.Field("FastIoUnlockAllByKey").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoUnlockAllByKey);
            GetAddressInfo(FastIoDispatch.Field("FastIoDeviceControl").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoDeviceControl);
            GetAddressInfo(FastIoDispatch.Field("AcquireFileForNtCreateSection").GetPtr(), &mm_DriverInfo.FastIoDispatch.AcquireFileForNtCreateSection);
            GetAddressInfo(FastIoDispatch.Field("ReleaseFileForNtCreateSection").GetPtr(), &mm_DriverInfo.FastIoDispatch.ReleaseFileForNtCreateSection);
            GetAddressInfo(FastIoDispatch.Field("FastIoDetachDevice").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoDetachDevice);
            GetAddressInfo(FastIoDispatch.Field("FastIoQueryNetworkOpenInfo").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoQueryNetworkOpenInfo);
            GetAddressInfo(FastIoDispatch.Field("AcquireForModWrite").GetPtr(), &mm_DriverInfo.FastIoDispatch.AcquireForModWrite);
            GetAddressInfo(FastIoDispatch.Field("MdlRead").GetPtr(), &mm_DriverInfo.FastIoDispatch.MdlRead);
            GetAddressInfo(FastIoDispatch.Field("MdlReadComplete").GetPtr(), &mm_DriverInfo.FastIoDispatch.MdlReadComplete);
            GetAddressInfo(FastIoDispatch.Field("PrepareMdlWrite").GetPtr(), &mm_DriverInfo.FastIoDispatch.PrepareMdlWrite);
            GetAddressInfo(FastIoDispatch.Field("MdlWriteComplete").GetPtr(), &mm_DriverInfo.FastIoDispatch.MdlWriteComplete);
            GetAddressInfo(FastIoDispatch.Field("FastIoReadCompressed").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoReadCompressed);
            GetAddressInfo(FastIoDispatch.Field("FastIoWriteCompressed").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoWriteCompressed);
            GetAddressInfo(FastIoDispatch.Field("MdlReadCompleteCompressed").GetPtr(), &mm_DriverInfo.FastIoDispatch.MdlReadCompleteCompressed);
            GetAddressInfo(FastIoDispatch.Field("MdlWriteCompleteCompressed").GetPtr(), &mm_DriverInfo.FastIoDispatch.MdlWriteCompleteCompressed);
            GetAddressInfo(FastIoDispatch.Field("FastIoQueryOpen").GetPtr(), &mm_DriverInfo.FastIoDispatch.FastIoQueryOpen);
            GetAddressInfo(FastIoDispatch.Field("ReleaseForModWrite").GetPtr(), &mm_DriverInfo.FastIoDispatch.ReleaseForModWrite);
            GetAddressInfo(FastIoDispatch.Field("AcquireForCcFlush").GetPtr(), &mm_DriverInfo.FastIoDispatch.AcquireForCcFlush);
            GetAddressInfo(FastIoDispatch.Field("ReleaseForCcFlush").GetPtr(), &mm_DriverInfo.FastIoDispatch.ReleaseForCcFlush);
        }

        ReadPointersVirtual(_countof(MajorFunction), m_TypedObject.Field("MajorFunction").GetPointerTo().GetPtr(), MajorFunction);

        for (ULONG i = 0; i < _countof(mm_DriverInfo.MajorFunction); i++) {

            GetAddressInfo(MajorFunction[i], &mm_DriverInfo.MajorFunction[i]);
        }
    }
    catch (...) {

    }
}

MsDriverObject::~MsDriverObject(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    None.

--*/
{
    Clear();
    /*
    if (m_Image)
    {
    // free(m_Image);
    // m_Image = NULL;
    // http://stackoverflow.com/questions/9331561/why-does-my-classs-destructor-get-called-when-i-add-instances-to-a-vector
    // http://stackoverflow.com/questions/15277606/c-vector-of-objects-and-excessive-calls-to-destructor

    Clear();
    }
    */
}


vector<MsDriverObject>
GetDrivers(
)
/*++

Routine Description:

    Description.

Arguments:

    - 

Return Value:

    vector<MsDriverObject>.

--*/
{
    vector<HANDLE_OBJECT> DriverObjects = ObOpenObjectDirectory(ObGetDriverObject());
    vector<MsDriverObject> Drivers;
    vector<MsDllObject> DllList;
    ULONG64 Head = ExtNtOsInformation::GetKernelLoadedModuleListHead();

    if (IsValid(Head)) {

        try {

            ModuleIterator Dlls(Head);

            for (Dlls.First(); !Dlls.IsDone(); Dlls.Next()) {

                MsDllObject DllObject = Dlls.Current();
                DllList.push_back(DllObject);
            }
        }
        catch (...) {

        }
    }

    for each (HANDLE_OBJECT DriverObject in DriverObjects) {

        MsDriverObject Driver(DriverObject.ObjectPtr);

        Driver.GetInfoFull();
        Driver.RtlGetExports();
        Driver.RtlGetImports(DllList);

        Drivers.push_back(Driver);
    }

    DriverObjects = ObOpenObjectDirectory(ObGetFileSystemObject());

    for each (HANDLE_OBJECT DriverObject in DriverObjects) {

        if (0 == wcscmp(DriverObject.Type, L"Driver")) {

            MsDriverObject Driver(DriverObject.ObjectPtr);

            Driver.GetInfoFull();
            Driver.RtlGetExports();
            Driver.RtlGetImports(DllList);

            Drivers.push_back(Driver);
        }
    }

    return Drivers;
}
