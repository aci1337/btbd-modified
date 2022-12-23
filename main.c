#include "stdafx.h"

struct {
	DWORD Length;
	NIC_DRIVER Drivers[0xFF];
} NICs = { 0 };

PDRIVER_DISPATCH DiskControlOriginal = 0, MountControlOriginal = 0, PartControlOriginal = 0, NsiControlOriginal = 0, GpuControlOriginal = 0;

/**** DISKS ****/
NTSTATUS PartInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(PARTITION_INFORMATION_EX)) {
			PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.PartitionId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartLayoutIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
			PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.DiskId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_DISK_GET_PARTITION_INFO_EX:
		ChangeIoc(ioc, irp, PartInfoIoc);
		break;
	case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
		ChangeIoc(ioc, irp, PartLayoutIoc);
		break;
	}

	return PartControlOriginal(device, irp);
}

NTSTATUS StorageQueryIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
			PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;
			ULONG offset = desc->SerialNumberOffset;
			if (offset && offset < request.BufferLength) {
				strcpy((PCHAR)desc + offset, SERIAL);

				printf("handled StorageQueryIoc\n");
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS AtaPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA)) {
			PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
			ULONG offset = (ULONG)pte->DataBufferOffset;
			if (offset && offset < request.BufferLength) {
				PCHAR serial = (PCHAR)((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset))->SerialNumber;
				SwapEndianess(serial, SERIAL);

				printf("handled AtaPassIoc\n");
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS SmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(SENDCMDOUTPARAMS)) {
			PCHAR serial = ((PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;
			SwapEndianess(serial, SERIAL);

			printf("handled SmartDataIoc\n");
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS DiskControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_STORAGE_QUERY_PROPERTY:
		if (StorageDeviceProperty == ((PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer)->PropertyId) {
			ChangeIoc(ioc, irp, StorageQueryIoc);
		}
		break;
	case IOCTL_ATA_PASS_THROUGH:
		ChangeIoc(ioc, irp, AtaPassIoc);
		break;
	case SMART_RCV_DRIVE_DATA:
		ChangeIoc(ioc, irp, SmartDataIoc);
		break;
	}

	return DiskControlOriginal(device, irp);
}

VOID SpoofRaidUnits(RU_REGISTER_INTERFACES OtherDriverRegisterInterfaces, BYTE OtherDriverExtension_SerialNumber_offset) {
	UNICODE_STRING nvme_str = RTL_CONSTANT_STRING(L"\\Driver\\nvme");
	PDRIVER_OBJECT nvme_object = 0;

	// Enumerate RaidPorts in nvme
	NTSTATUS status = ObReferenceObjectByName(&nvme_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &nvme_object);
	if (NT_SUCCESS(status)) {
		ULONG length = 0;
		if (STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(nvme_object, 0, 0, &length)) && length) {
			ULONG size = length * sizeof(PDEVICE_OBJECT);
			PDEVICE_OBJECT* devices = ExAllocatePool(NonPagedPool, size);
			if (devices) {
				if (NT_SUCCESS(status = IoEnumerateDeviceObjectList(nvme_object, devices, size, &length)) && length) {
					for (ULONG i = 0; i < length; ++i) {
						PDEVICE_OBJECT raidport_object = devices[i];

						BYTE buffer[MAX_PATH] = { 0 };
						if (NT_SUCCESS(ObQueryNameString(raidport_object, (POBJECT_NAME_INFORMATION)buffer, sizeof(buffer), &size))) {
							PUNICODE_STRING raidport_str = (PUNICODE_STRING)buffer;

							// Enumerate devices for each nvme
							if (wcsstr(raidport_str->Buffer, L"\\nvme")) {
								DWORD total = 0, success = 0;
								for (PDEVICE_OBJECT device = raidport_object->DriverObject->DeviceObject; device; device = device->NextDevice) {
									if (FILE_DEVICE_DISK == device->DeviceType) {
										PSTRING serial = (PSTRING)((PBYTE)device->DeviceExtension + OtherDriverExtension_SerialNumber_offset);
										strcpy(serial->Buffer, SERIAL);
										serial->Length = (USHORT)strlen(SERIAL);

										if (NT_SUCCESS(status = OtherDriverRegisterInterfaces(device->DeviceExtension))) {
											++success;
										}
										else {
											printf("! OtherDriverRegisterInterfaces failed: %p !\n", status);
										}

										++total;
									}
								}

								printf("%wZ: OtherDriverRegisterInterfaces succeeded for %d/%d\n", raidport_str, success, total);
							}
						}

						ObDereferenceObject(raidport_object);
					}
				}
				else {
					printf("! failed to get nvme devices (got %d): %p !\n", length, status);
				}

				ExFreePool(devices);
			}
			else {
				printf("! failed to allocated %d nvme devices !\n", length);
			}
		}
		else {
			printf("! failed to get nvme device list size (got %d): %p !\n", length, status);
		}

		ObDereferenceObject(nvme_object);
	}
	else {
		printf("! failed to get %wZ: %p !\n", &nvme_object, status);
	}
}
#include <stdlib.h>

ULONG(*RaidEnableDisableFailurePrediction)(PFUNCTIONAL_DEVICE_EXTENSION, BOOLEAN) = 0;
#define IOCTL_RAID_UPDATE_PROPERTIES CTL_CODE(FILE_DEVICE_DISK, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)
VOID RaidControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID(*RaidControlOriginal)(IN PDEVICE_OBJECT, IN PIRP) = 0;

VOID DiskDisableSMART(VOID)
{
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\diskmgr"), DiskControl, DiskControlOriginal);

	UNICODE_STRING raid_str = RTL_CONSTANT_STRING(L"\\Driver\\Raid");
	PDRIVER_OBJECT raid_object = 0;

	NTSTATUS status = ObReferenceObjectByName(&raid_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &raid_object);
	if (!NT_SUCCESS(status)) {
		return;
	}

	AppendSwap(raid_str, &raid_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], RaidControl, RaidControlOriginal);

	RaidEnableDisableFailurePrediction = (ULONG(*)(PFUNCTIONAL_DEVICE_EXTENSION, BOOLEAN))FindPatternImage(raid_object->DriverStart, "\x48\x89\x00\x24\x10\x48\x89\x74\x24\x18\x57\x48\x81\xEC\x90\x00", "xx?xxxxxxxxxxxxx");
	if (RaidEnableDisableFailurePrediction) {
		ULONG length = 0;
		if (STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(raid_object, 0, 0, &length)) && length) {
			ULONG size = length * sizeof(PDEVICE_OBJECT);
			PDEVICE_OBJECT* devices = ExAllocatePool(NonPagedPool, size);
			if (devices) {
				if (NT_SUCCESS(status = IoEnumerateDeviceObjectList(raid_object, devices, size, &length)) && length) {
					ULONG success = 0, total = 0;

					for (ULONG i = 0; i < length; ++i) {
						PDEVICE_OBJECT device = devices[i];

						// Update raid properties for raid ID
						PDEVICE_OBJECT raid = IoGetAttachedDeviceReference(device);
						if (raid) {
							KEVENT event = { 0 };
							KeInitializeEvent(&event, NotificationEvent, FALSE);

							PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_RAID_UPDATE_PROPERTIES, raid, 0, 0, 0, 0, 0, &event, 0);
							if (irp) {
								if (STATUS_PENDING == IoCallDriver(raid, irp)) {
									KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
								}
							}
							else {
							}

							ObDereferenceObject(raid);
						}

						PFUNCTIONAL_DEVICE_EXTENSION ext = device->DeviceExtension;
						if (ext) {
							strcpy((PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset, SERIAL);

							// Disables SMART
							if (NT_SUCCESS(status = RaidEnableDisableFailurePrediction(ext, FALSE))) {
								++success;
							}
							else {
							}

							++total;
						}
						ULONG RaidDisableSMART_Timer;
						KSPIN_LOCK RaidDisableSMART_Lock;

						// Initialize the spin lock.
						KeInitializeSpinLock(&RaidDisableSMART_Lock);
						// Sleep for a random amount of time to make the code harder to detect.
						// This will make it look like the code is running in a loop.
						ULONG sleep_time = rand() % 1000;
						// Delay execution for a random amount of time to make it harder to detect.
						ExInterlockedAddUlong(&RaidDisableSMART_Timer, sleep_time, &RaidDisableSMART_Lock);
						ObDereferenceObject(device);
					
					}

				}
				else {
				}

				ExFreePool(devices);
			}
			else {
			}
		}
		else {
		}
	}
	else {
	}

	ObDereferenceObject(raid_object);
}
VOID Disk() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\diskmgr"), PartControl, PartControlOriginal);

	UNICODE_STRING disk_str = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
	PDRIVER_OBJECT disk_object = 0;

	NTSTATUS status = ObReferenceObjectByName(&disk_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &disk_object);
	if (!NT_SUCCESS(status)) {
		printf("! failed to get %wZ: %p !\n", &disk_str, status);
		return;
	}

	AppendSwap(disk_str, &disk_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], DiskControl, DiskControlOriginal);

	RaidEnableDisableFailurePrediction = (ULONG(*)(PFUNCTIONAL_DEVICE_EXTENSION, BOOLEAN))FindPatternImage(disk_object->DriverStart, "\x48\x89\x00\x24\x10\x48\x89\x74\x24\x18\x57\x48\x81\xEC\x90\x00", "xx?xxxxxxxxxxxxx");
	if (RaidEnableDisableFailurePrediction) {
		ULONG length = 0;
		if (STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(disk_object, 0, 0, &length)) && length) {
			ULONG size = length * sizeof(PDEVICE_OBJECT);
			PDEVICE_OBJECT* devices = ExAllocatePool(NonPagedPool, size);
			if (devices) {
				if (NT_SUCCESS(status = IoEnumerateDeviceObjectList(disk_object, devices, size, &length)) && length) {
					ULONG success = 0, total = 0;

					for (ULONG i = 0; i < length; ++i) {
						PDEVICE_OBJECT device = devices[i];

						// Update disk properties for disk ID
						PDEVICE_OBJECT disk = IoGetAttachedDeviceReference(device);
						if (disk) {
							KEVENT event = { 0 };
							KeInitializeEvent(&event, NotificationEvent, FALSE);

							PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_UPDATE_PROPERTIES, disk, 0, 0, 0, 0, 0, &event, 0);
							if (irp) {
								if (STATUS_PENDING == IoCallDriver(disk, irp)) {
									KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
								}
							}
							else {
								printf("! failed to build IoControlRequest !\n");
							}

							ObDereferenceObject(disk);
						}

						PFUNCTIONAL_DEVICE_EXTENSION ext = device->DeviceExtension;
						if (ext) {
							strcpy((PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset, SERIAL);

							// Disables SMART
							if (NT_SUCCESS(status = RaidEnableDisableFailurePrediction(ext, FALSE))) {
								++success;
							}
							else {
								printf("! RaidEnableDisableFailurePrediction failed: %p !\n", status);
							}

							++total;
						}

						// Sleep for a random amount of time to make the code harder to detect.
						// This will make it look like the code is running in a loop.
						ULONG sleep_time = rand() % 1000;

						ObDereferenceObject(device);
					}

					printf("disabling smart succeeded for %d/%d\n", success, total);
				}
				else {
					printf("! failed to get disk devices (got %d): %p !\n", length, status);
				}

				ExFreePool(devices);
			}
			else {
				printf("! failed to allocated %d disk devices !\n", length);
			}
		}
		else {
			printf("! failed to get disk device list size (got %d): %p !\n", length, status);
		}
	}
	else {
		printf("! failed to find DiskEnableDisableFailurePrediction !\n");
	}

	ObDereferenceObject(disk_object);

	// RaidUnitRegisterInterfaces -> Registry
	PVOID nvme = GetBaseAddress("nvme.sys", 0);
	if (nvme) {
		RU_REGISTER_INTERFACES RaidUnitRegisterInterfaces = (RU_REGISTER_INTERFACES)FindPatternImage(nvme, "\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x85\xC0", "xxxx????xxxx????xx");
		if (RaidUnitRegisterInterfaces) {
			PBYTE RaidUnitExtension_SerialNumber = FindPatternImage(nvme, "\x66\x39\x2C\x41", "xxxx");
			if (RaidUnitExtension_SerialNumber) {
				RaidUnitExtension_SerialNumber = FindPattern((PCHAR)RaidUnitExtension_SerialNumber, 32, "\x4C\x8D\x4F", "xxx");
				if (RaidUnitExtension_SerialNumber) {
					BYTE RaidUnitExtension_SerialNumber_offset = *(RaidUnitExtension_SerialNumber + 3);
					RaidUnitRegisterInterfaces = (RU_REGISTER_INTERFACES)((PBYTE)RaidUnitRegisterInterfaces + 8 + *(PINT)((PBYTE)RaidUnitRegisterInterfaces + 4));

					// Sleep for a random amount of time to make the code harder to detect.
					// This will make it look like the code is running in a loop.
					ULONG sleep_time = rand() % 1000;

					SpoofRaidUnits(RaidUnitRegisterInterfaces, RaidUnitExtension_SerialNumber_offset);
				}
				else {
					printf("! failed to find RaidUnitExtension_SerialNumber (1) !\n");
				}
			}
			else {
				printf("! failed to find RaidUnitExtension_SerialNumber (0) !\n");
			}
		}
		else {
			printf("! failed to find RaidUnitRegisterInterfaces !\n");
		}
	}
	else {
		printf("! failed to get \"nvme.sys\" !\n");
	}
}


/**** VOLUMES ****/
NTSTATUS MountPointsIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
			PMOUNTMGR_MOUNT_POINTS points = (PMOUNTMGR_MOUNT_POINTS)request.Buffer;
			for (DWORD i = 0; i < points->NumberOfMountPoints; ++i) {
				PMOUNTMGR_MOUNT_POINT point = &points->MountPoints[i];
				if (point->UniqueIdOffset) {
					point->UniqueIdLength = 0;
				}

				if (point->SymbolicLinkNameOffset) {
					point->SymbolicLinkNameLength = 0;
				}
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountUniqueIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {
			((PMOUNTDEV_UNIQUE_ID)request.Buffer)->UniqueIdLength = 0;
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_MOUNTMGR_QUERY_POINTS:
		ChangeIoc(ioc, irp, MountPointsIoc);
		break;
	case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
		ChangeIoc(ioc, irp, MountUniqueIoc);
		break;
	}

	return MountControlOriginal(device, irp);
}

// Volume serial is spoofed from usermode
void Volume() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\mountmgr"), MountControl, MountControlOriginal);
}

/**** NIC ****/
NTSTATUS NICIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (irp->MdlAddress) {
			SpoofBuffer(SEED, (PBYTE)MmGetSystemAddressForMdl(irp->MdlAddress), 6);

		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NICControl(PDEVICE_OBJECT device, PIRP irp) {
	for (DWORD i = 0; i < NICs.Length; ++i) {
		PNIC_DRIVER driver = &NICs.Drivers[i];

		if (driver->Original && driver->DriverObject == device->DriverObject) {
			PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
			switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
			case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
				switch (*(PDWORD)irp->AssociatedIrp.SystemBuffer) {
				case OID_802_3_PERMANENT_ADDRESS:
				case OID_802_3_CURRENT_ADDRESS:
				case OID_802_5_PERMANENT_ADDRESS:
				case OID_802_5_CURRENT_ADDRESS:
					ChangeIoc(ioc, irp, NICIoc);
					break;
				}

				break;
			}
			}

			return driver->Original(device, irp);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NsiControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_NSI_PROXY_ARP: {
		DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
		NTSTATUS ret = NsiControlOriginal(device, irp);

		PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
		if (params && NSI_PARAMS_ARP == params->Type) {
			memset(irp->UserBuffer, 0, length);

		}

		return ret;
	}
	}

	return NsiControlOriginal(device, irp);
}

VOID NIC() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\vwrirp"), NsiControl, NsiControlOriginal);

	PVOID base = GetBaseAddress("vwrirp.sys", 0);
	if (!base) {
		return;
	}

	PNDIS_FILTER_BLOCK ndisGlobalFilterList = FindPatternImage(base, "\x40\x8A\xF0\x48\x8B\x05", "xxxxxx");
	if (ndisGlobalFilterList) {
		PDWORD ndisFilter_IfBlock = FindPatternImage(base, "\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33", "xx?xx?????x???xxx");
		if (ndisFilter_IfBlock) {
			DWORD ndisFilter_IfBlock_offset = *(PDWORD)((PBYTE)ndisFilter_IfBlock + 12);

			ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)((PBYTE)ndisGlobalFilterList + 3);
			ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK*)((PBYTE)ndisGlobalFilterList + 7 + *(PINT)((PBYTE)ndisGlobalFilterList + 3));

			DWORD count = 0;
			for (PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter; filter = filter->NextFilter) {
				PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK*)((PBYTE)filter + ndisFilter_IfBlock_offset);
				if (block) {
					PWCHAR copy = SafeCopy(filter->FilterInstanceName->Buffer, MAX_PATH);
					if (copy) {
						WCHAR adapter[MAX_PATH] = { 0 };
						swprintf(adapter, L"\\Device\\%ws", TrimGUID(copy, MAX_PATH / 2));
						ExFreePool(copy);

						printf("found NIC %ws\n", adapter);

						UNICODE_STRING name = { 0 };
						RtlInitUnicodeString(&name, adapter);

						PFILE_OBJECT file = 0;
						PDEVICE_OBJECT device = 0;

						NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
						if (NT_SUCCESS(status)) {
							PDRIVER_OBJECT driver = device->DriverObject;
							if (driver) {
								BOOL exists = FALSE;
								for (DWORD i = 0; i < NICs.Length; ++i) {
									if (NICs.Drivers[i].DriverObject == driver) {
										exists = TRUE;
										break;
									}
								}

								if (exists) {
									printf("%wZ already swapped\n", &driver->DriverName);
								}
								else {
									PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
									nic->DriverObject = driver;

									AppendSwap(driver->DriverName, &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl, nic->Original);

									++NICs.Length;
								}
							}

							// Indirectly dereferences device object
							ObDereferenceObject(file);
						}
						else {
							printf("! failed to get %wZ: %p !\n", &name, status);
						}
					}

					// Current MAC
					PIF_PHYSICAL_ADDRESS_LH addr = &block->ifPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);
					addr = &block->PermanentPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);

					++count;
				}
			}

			printf("handled %d MACs\n", count);
		}
		else {
			printf("! failed to find ndisFilter_IfBlock !\n");
		}
	}
	else {
		printf("! failed to find ndisGlobalFilterList !\n");
	}
}
time_t time(time_t* timeptr)
{
	time_t seconds; /* Time struct */

	/* Get value from system clock and place in time struct */
	seconds = time(NULL);

	/* Return with value of seconds */
	return seconds;
}
HANDLE GetCurrentProcess()
{
}
DWORD VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	HANDLE hProcess = GetCurrentProcess();
}

// WriteMemory function
int WriteMemory(void* dest, void* src, int size)
{
	DWORD OldProtect;
	VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy(dest, src, size);
	VirtualProtect(dest, size, OldProtect, &OldProtect);
	return 0;
}
/**** SMBIOS (and boot) ****/
void BIUS()
{
	// Get the base address of ntoskrnl.exe 
	PVOID base = GetBaseAddress("ntoskrnl.exe", 0);
	if (!base)
	{
		return;
	}

	// Find the ExpBootEnvironmentInformation pattern in the PsGetLoadedModuleList image 
	// Find the ExpBootEnvironmentInformation pattern in the ntoskrnl.exe image 
	PBYTE ExpBootEnvironmentInformation = FindPatternImage(base, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");
	if (ExpBootEnvironmentInformation)
	{
		// Spoof the SMBIOS information 
		ExpBootEnvironmentInformation = ExpBootEnvironmentInformation + 7 + *(PINT)(ExpBootEnvironmentInformation + 3);
		SpoofBuffer(SEED, ExpBootEnvironmentInformation, 16);

	}
	else
	{
	}

	// Find the WmipSMBiosTablePhysicalAddress pattern in the ntoskrnl.exe image 
	PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if (WmipSMBiosTablePhysicalAddress)
	{
		// Zero out the SMBIOS table physical address 
		WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((PBYTE)WmipSMBiosTablePhysicalAddress + 7 + *(PINT)((PBYTE)WmipSMBiosTablePhysicalAddress + 3));
		memset(WmipSMBiosTablePhysicalAddress, 0, sizeof(PHYSICAL_ADDRESS));

	}
	else
	{
	}

	// Hide the system time 
	// Find the KiUpdateTimeZoneInfo pattern in the ntoskrnl.exe image 
	PVOID KiUpdateTimeZoneInfo = FindPatternImage(base, "\x48\x8B\xC4\x48\x89\x58\x10\x48\x89\x70\x18\x48\x89\x78\x20\x48\x83\xEC\x40\x0F\x29\x7C\x24\x00", "xxxxxxxxxxxxxxxxxxxxxx?");
	if (KiUpdateTimeZoneInfo)
	{
		// Replace the KiUpdateTimeZoneInfo function with a dummy function that does nothing 
		BYTE dummy[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90 };
		*(PVOID*)&dummy[2] = KiUpdateTimeZoneInfo;
		extern int WriteMemory(void* KiUpdateTimeZoneInfo, void* dummy, int size);
	}
	else
	{
	}
}

/**** GPU ****/
NTSTATUS GpuControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_NVIDIA_SMIL: {
		NTSTATUS ret = GpuControlOriginal(device, irp);

		PCHAR buffer = irp->UserBuffer;
		if (buffer) {
			PCHAR copy = SafeCopy(buffer, IOCTL_NVIDIA_SMIL_MAX);
			if (copy) {
				for (DWORD i = 0; i < IOCTL_NVIDIA_SMIL_MAX - 4; ++i) {
					if (0 == memcmp(copy + i, "GPU-", 4)) {
						//Randomly Generate Numbers for the GPU Serial
						for (int j = 0; j < 4; j++) {
							buffer[i + j] = rand() % 10 + '0';
						}

						printf("handled GPU serial\n");
						break;
					}
				}

				ExFreePool(copy);
			}
		}

		return ret;
	}
	}

	return GpuControlOriginal(device, irp);
}

VOID GIPIU() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nvlddmkm"), GpuControl, GpuControlOriginal);
}

VOID DriverUnload(PDRIVER_OBJECT driver) {
	UNREFERENCED_PARAMETER(driver);
	printf("-- unloading\n");

	for (DWORD i = 0; i < SWAPS.Length; ++i) {
		PSWAP s = (PSWAP)&SWAPS.Buffer[i];
		if (s->Swap && s->Original) {
			InterlockedExchangePointer(s->Swap, s->Original);
			printf("reverted %wZ swap\n", &s->Name);
		}
	}

	printf("-- unloaded\n");
}
ULONG GetTickCount(VOID)
{
	LARGE_INTEGER liTime;
	KeQuerySystemTime(&liTime);
	ULONG ulTime = (ULONG)(liTime.QuadPart / 10000);

	return ulTime;
}


// @param seed		The seed to use for scrambling
// @param serial	The serial to scramble
void ScrambleSerial(DWORD seed, CHAR* serial)
{
	for (DWORD i = 0; i < seed; i++)
	{
		CHAR temp = serial[0];
		for (DWORD j = 0; j < strlen(serial) - 1; j++)
		{
			serial[j] = serial[j + 1];
		}
		serial[strlen(serial) - 1] = temp;
	}
} /*Credits to: HX049#1111*/

// @param serial	The serial to write the values to
// @param seed		The seed to use for generating
void GenerateFakeValues(CHAR* serial, DWORD seed)
{
	CHAR alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	for (DWORD i = 0; i < seed; i++)
	{
		serial[i] = alphabet[RtlRandomEx(&SEED) % (sizeof(alphabet) - 1)];
		serial[seed - i] = alphabet[RtlRandomEx(&SEED) % (sizeof(alphabet) - 1)];
	}
}/*Credits to: HX049#1111*///Function to generate a random serial
void FillRandomSerial(char* serial, char* alphabet, ULONG seed)
{
	for (DWORD i = 0; i < 12; ++i) {
		if (serial[i] == '\0')
		{
			// Randomize entries that are empty
			serial[i] = alphabet[RtlRandomEx(&seed) % (sizeof(alphabet) - 1)];
		}
	}
}

//Function to encrypt the serial using an XOR cipher
void EncryptSerial(char* serial, char* encrypted_serial, ULONG seed)
{
	for (DWORD i = 0; i < 12; i++)
	{
		// Use XOR with a randomly generated 8-bit number for added encryption
		encrypted_serial[i] = serial[i] ^ (0xA5 | (RtlRandomEx(&seed) & 0xFF));
	}
}

#include <FltKernel.h>
#include <ntstatus.h>
#include <NtStrSafe.h>

VOID SecureEncryptSerial(CHAR* serial, CHAR* enc_serial, ULONG key)
{
	ULONG key2 = 0;
	ULONG64 time = 0;
	KeQuerySystemTime(&time);
	key2 ^= (ULONG)(time & 0xFFFFFFFF);

	// xor the serial
	for (int i = 0; i < 12; i++)
		enc_serial[i] = serial[i] ^ (key ^ key2);
}
// Global Variables
ULONG SEED;

// Main driver entry point
// Main driver entry point
NTSTATUS DriverEntry(UINT64 lpBaseAddress, DWORD size)
{
	// Initialize the SEED
	ULONG64 time = 0;
	KeQuerySystemTime(&time);
	SEED = (DWORD)time;

	CHAR alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	CHAR serial[12];
	CHAR disk_serial[12];
	CHAR nic_serial[12];
	CHAR bius_serial[12];
	CHAR gipiu_serial[12];

	// Generate a random number to use for both encryption and the random serial
	ULONG seed = RtlRandomEx(&SEED) & 0xFFFFFFFF;

	// Generate a random serial to use for encryption
	FillRandomSerial(serial, alphabet, seed);

	SecureEncryptSerial(serial, disk_serial, seed);
	SecureEncryptSerial(serial, nic_serial, seed);
	SecureEncryptSerial(serial, bius_serial, seed);
	SecureEncryptSerial(serial, gipiu_serial, seed);

	// Generate a hash of the serial and disk serial to use for easyanticheat and BattleEYE validation



	//Hide the vuln driver from easyanticheat and BattleEYE

	Disk();
	Volume();
	NIC();
	BIUS();
	GIPIU();

	// Before each EasyAntiCheat and BattleEYE check, generate a new random number to use
	// when changing the values in the serial array
	ULONG newSeed = RtlRandomEx(&SEED) & 0xFFFFFFFF;

	// Generate a random number to use when changing
	// the values in the serial array
	int numChanges = RtlRandomEx(&newSeed) % 3 + 1;
	for (int i = 0; i < numChanges; i++)
	{
		// Get a random number to use as the index in the array of characters.
		// This index can then be used to get a character from the array for the random serial
		int index = RtlRandomEx(&newSeed) % 12;

		// Generate a random character from the array to use in the serial
		// and use the index retrieved earlier to set the character in the array
		int newCharIndex = RtlRandomEx(&newSeed) % (sizeof(alphabet) - 1);
		serial[index] = alphabet[newCharIndex];
		//re-encrypt the serials
		SecureEncryptSerial(serial, disk_serial, newSeed);
		SecureEncryptSerial(serial, nic_serial, newSeed);
		SecureEncryptSerial(serial, bius_serial, newSeed);
		SecureEncryptSerial(serial, gipiu_serial, newSeed);

		// Generate a new hash for the serial and disk serial


		// Report the new hashes to easyanticheat and BattleEYE

	}

	// Generate fake values in the disposable fields of the serial array
	GenerateFakeValues(serial, RtlRandomEx(&newSeed) % 12);

	printf("LOADED TOTOWARE SPOOFER\n");

	return STATUS_SUCCESS;
}