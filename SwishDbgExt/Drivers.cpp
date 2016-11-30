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

    - Ob.cpp

Abstract:

    - http://msdn.microsoft.com/en-us/windows/ff553536(v=vs.71).aspx

Environment:

    - User mode

Revision History:

    - Matthieu Suiche
--*/

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
    m_ObjectPtr = m_TypedObject.GetPtr();

    mm_DriverInfo.DeviceObject = m_TypedObject.Field("DeviceObject").GetPtr();
    mm_DriverInfo.DriverStart = m_TypedObject.Field("DriverStart").GetPtr();
    mm_DriverInfo.DriverSize = m_TypedObject.Field("DriverSize").GetUlong();
    mm_DriverInfo.DriverSection = m_TypedObject.Field("DriverSection").GetPtr();
    mm_DriverInfo.DriverExtension = m_TypedObject.Field("DriverExtension").GetPtr();

    ExtRemoteTypedEx::GetUnicodeString(m_TypedObject.Field("DriverName"),
                                        (PWSTR)&mm_DriverInfo.DriverName,
                                        sizeof(mm_DriverInfo.DriverName));

    if (m_TypedObject.Field("FastIoDispatch").GetPtr())
    {
        ExtRemoteTyped FastIoDispatch = m_TypedObject.Field("FastIoDispatch");

        mm_DriverInfo.FastIoDispatch.FastIoCheckIfPossible = FastIoDispatch.Field("FastIoCheckIfPossible").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoRead = FastIoDispatch.Field("FastIoRead").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoWrite = FastIoDispatch.Field("FastIoWrite").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoQueryBasicInfo = FastIoDispatch.Field("FastIoQueryBasicInfo").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoQueryStandardInfo = FastIoDispatch.Field("FastIoQueryStandardInfo").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoLock = FastIoDispatch.Field("FastIoLock").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoUnlockSingle = FastIoDispatch.Field("FastIoUnlockSingle").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoUnlockAll = FastIoDispatch.Field("FastIoUnlockAll").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoUnlockAllByKey = FastIoDispatch.Field("FastIoUnlockAllByKey").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoDeviceControl = FastIoDispatch.Field("FastIoDeviceControl").GetPtr();
        mm_DriverInfo.FastIoDispatch.AcquireFileForNtCreateSection = FastIoDispatch.Field("AcquireFileForNtCreateSection").GetPtr();
        mm_DriverInfo.FastIoDispatch.ReleaseFileForNtCreateSection = FastIoDispatch.Field("ReleaseFileForNtCreateSection").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoDetachDevice = FastIoDispatch.Field("FastIoDetachDevice").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoQueryNetworkOpenInfo = FastIoDispatch.Field("FastIoQueryNetworkOpenInfo").GetPtr();
        mm_DriverInfo.FastIoDispatch.AcquireForModWrite = FastIoDispatch.Field("AcquireForModWrite").GetPtr();
        mm_DriverInfo.FastIoDispatch.MdlRead = FastIoDispatch.Field("MdlRead").GetPtr();
        mm_DriverInfo.FastIoDispatch.MdlReadComplete = FastIoDispatch.Field("MdlReadComplete").GetPtr();
        mm_DriverInfo.FastIoDispatch.PrepareMdlWrite = FastIoDispatch.Field("PrepareMdlWrite").GetPtr();
        mm_DriverInfo.FastIoDispatch.MdlWriteComplete = FastIoDispatch.Field("MdlWriteComplete").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoReadCompressed = FastIoDispatch.Field("FastIoReadCompressed").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoWriteCompressed = FastIoDispatch.Field("FastIoWriteCompressed").GetPtr();
        mm_DriverInfo.FastIoDispatch.MdlReadCompleteCompressed = FastIoDispatch.Field("MdlReadCompleteCompressed").GetPtr();
        mm_DriverInfo.FastIoDispatch.MdlWriteCompleteCompressed = FastIoDispatch.Field("MdlWriteCompleteCompressed").GetPtr();
        mm_DriverInfo.FastIoDispatch.FastIoQueryOpen = FastIoDispatch.Field("FastIoQueryOpen").GetPtr();
        mm_DriverInfo.FastIoDispatch.ReleaseForModWrite = FastIoDispatch.Field("ReleaseForModWrite").GetPtr();
        mm_DriverInfo.FastIoDispatch.AcquireForCcFlush = FastIoDispatch.Field("AcquireForCcFlush").GetPtr();
        mm_DriverInfo.FastIoDispatch.ReleaseForCcFlush = FastIoDispatch.Field("ReleaseForCcFlush").GetPtr();
    }

    mm_DriverInfo.DriverInit = m_TypedObject.Field("DriverInit").GetPtr();
    mm_DriverInfo.DriverStartIo = m_TypedObject.Field("DriverStartIo").GetPtr();
    mm_DriverInfo.DriverUnload = m_TypedObject.Field("DriverUnload").GetPtr();

    ReadPointersVirtual(sizeof(mm_DriverInfo.MajorFunction) / sizeof(mm_DriverInfo.MajorFunction[0]),
                                       m_TypedObject.Field("MajorFunction").GetPointerTo().GetPtr(),
                                       mm_DriverInfo.MajorFunction);


    if (mm_DriverInfo.DriverSection)
    {
        ExtRemoteTyped LdrData("(nt!_LDR_DATA_TABLE_ENTRY *)@$extin", mm_DriverInfo.DriverSection);
        m_ImageBase = LdrData.Field("DllBase").GetPtr();
        m_ImageSize = LdrData.Field("SizeOfImage").GetUlong();

        ExtRemoteTypedEx::GetUnicodeString(LdrData.Field("FullDllName"),
            (PWSTR)&mm_DriverInfo.FullDllName,
            sizeof(mm_DriverInfo.FullDllName));

        ExtRemoteTypedEx::GetUnicodeString(LdrData.Field("BaseDllName"),
            (PWSTR)&mm_DriverInfo.DllName,
            sizeof(mm_DriverInfo.DllName));
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

    for each (HANDLE_OBJECT DriverObject in DriverObjects)
    {
        MsDriverObject Driver(DriverObject.ObjectPtr);

        Drivers.push_back(Driver);
    }

    return Drivers;
}