#include "driver.hpp"

inline PDRIVER_OBJECT g_driver_object{ };
inline PVOID g_registration_handle{ };

static KLDR_DATA_TABLE_ENTRY g_driver_entry{ };

NTSTATUS device_create_callback( PDEVICE_OBJECT device_object, PIRP irp )
{
	ClearFlag( device_object->Flags, DO_DEVICE_INITIALIZING );

	IoCompleteRequest( irp, IO_NO_INCREMENT );

	return STATUS_SUCCESS;
}

NTSTATUS device_control_callback( PDEVICE_OBJECT device_object, PIRP irp )
{
	UNREFERENCED_PARAMETER( device_object );

	PIO_STACK_LOCATION irp_stack = current_irp_stack_location( irp );

	if ( !irp_stack ) {
		dbg_print( "[hotwheels] [!irp_stack!] Unknown" );

		return STATUS_ABANDONED;
	}

	ULONG io_ctl = irp_stack->Parameters.DeviceIoControl.IoControlCode;

	if ( io_ctl < IOCTL_WRITE_MEMORY || io_ctl > IOCTL_UNLOAD ) {
		// No need to do anything special here, windows will interact with our device.

		IoCompleteRequest( irp, IO_NO_INCREMENT );

		return STATUS_SUCCESS;
	}

	switch ( io_ctl ) {
	case IOCTL_WRITE_MEMORY: {
		WRITE_MEMORY_CALLBACK_INPUT* info = reinterpret_cast< WRITE_MEMORY_CALLBACK_INPUT* >( irp->AssociatedIrp.SystemBuffer );

		if ( !info ) {
			dbg_print( "[hotwheels] [!info!]" );

			break;
		}

		PEPROCESS process{ };
		PEPROCESS request_process{ };

		NTSTATUS return_code = lookup_process_by_process_id( info->pid, &process );

		if ( !NT_SUCCESS( return_code ) ) {
			dbg_print( "[hotwheels] [!lookup_process_by_process_id!] %ul", return_code );

			break;
		}

		return_code = lookup_process_by_process_id( reinterpret_cast< HANDLE >( IoGetRequestorProcessId( irp ) ), &request_process );

		if ( !NT_SUCCESS( return_code ) ) {
			dbg_print( "[hotwheels] [!lookup_process_by_process_id!] %ul", return_code );

			break;
		}

		if ( get_process_wow64_process( process ) ) {
			if ( !x86( info->address ) ) {
				dbg_print( "[hotwheels] [!x86!] " );

				break;
			}
		}

		SIZE_T return_bytes{ };
		return_code = copy_virtual_memory( request_process, info->memory_pointer, process, info->address, info->size, KernelMode, &return_bytes );

		if ( !NT_SUCCESS( return_code ) ) {
			dbg_print( "[hotwheels] [!copy_virtual_memory!] 0x%x 0x%x", return_code, info->address );

			break;
		}

		irp->IoStatus.Information = sizeof( WRITE_MEMORY_CALLBACK_INPUT );

		break;
	}

	case IOCTL_READ_MEMORY: {
		READ_MEMORY_CALLBACK_INPUT* info = reinterpret_cast< READ_MEMORY_CALLBACK_INPUT* >( irp->AssociatedIrp.SystemBuffer );

		if ( !info ) {
			dbg_print( "[hotwheels] [!info!]" );

			break;
		}

		PEPROCESS process{ };
		PEPROCESS request_process{ };

		NTSTATUS return_code = lookup_process_by_process_id( info->pid, &process );

		if ( !NT_SUCCESS( return_code ) ) {
			dbg_print( "[hotwheels] [!lookup_process_by_process_id!] %ul", return_code );

			break;
		}

		return_code = lookup_process_by_process_id( reinterpret_cast< HANDLE >( IoGetRequestorProcessId( irp ) ), &request_process );

		if ( !NT_SUCCESS( return_code ) ) {
			dbg_print( "[hotwheels] [!lookup_process_by_process_id!] %ul", return_code );

			break;
		}

		if ( get_process_wow64_process( process ) ) {
			if ( !x86( info->address ) ) {
				dbg_print( "[hotwheels] [!x86!] " );

				break;
			}
		}

		SIZE_T return_bytes{ };
		return_code = copy_virtual_memory( process, info->address, request_process, info->memory_pointer, info->size, KernelMode, &return_bytes );

		if ( !NT_SUCCESS( return_code ) ) {
			dbg_print( "[hotwheels] [!copy_virtual_memory!] 0x%x 0x%x %ul", return_code, info->address );

			break;
		}

		irp->IoStatus.Information = sizeof( READ_MEMORY_CALLBACK_INPUT );

		break;
	}

	case IOCTL_BASE_ADDRESS: {
		BASE_ADDRESS_CALLBACK_INPUT* info = reinterpret_cast< BASE_ADDRESS_CALLBACK_INPUT* >( irp->AssociatedIrp.SystemBuffer );

		if ( !info ) {
			dbg_print( "[hotwheels] [!info!]" );

			break;
		}

		PEPROCESS process{ };

		NTSTATUS return_code = lookup_process_by_process_id( info->pid, &process );

		if ( !NT_SUCCESS( return_code ) ) {
			dbg_print( "[hotwheels] [!lookup_process_by_process_id!] %ul", return_code );

			break;
		}

		if ( get_process_wow64_process( process ) ) {
			KeAttachProcess( process );

			PPEB32 peb32 = ( PPEB32 )get_process_wow64_process( process );

			if ( !peb32->Ldr ) {
				dbg_print( "[hotwheels] [!peb32->Ldr!]" );

				break;
			}

			for ( PLIST_ENTRY32 pListEntry = ( PLIST_ENTRY32 )( ( PPEB_LDR_DATA32 )peb32->Ldr )->InLoadOrderModuleList.Flink;
			      pListEntry != &( ( PPEB_LDR_DATA32 )peb32->Ldr )->InLoadOrderModuleList; pListEntry = ( PLIST_ENTRY32 )pListEntry->Flink ) {
				PLDR_DATA_TABLE_ENTRY32 entry = CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks );

				if ( wcscmp( reinterpret_cast< wchar_t* >( entry->BaseDllName.Buffer ), info->module ) == 0 ) {
					info->response = entry->DllBase;

					break;
				}
			}

			KeDetachProcess( );
		} else if ( get_process_peb( process ) ) {
			PEB* peb = get_process_peb( process );

			if ( !peb->Ldr ) {
				dbg_print( "[hotwheels] [!peb->Ldr!]" );

				break;
			}

			for ( auto list_entry = peb->Ldr->InLoadOrderModuleList.Flink; list_entry != &peb->Ldr->InLoadOrderModuleList;
			      list_entry      = list_entry->Flink ) {
				PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD( list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

				if ( wcscmp( reinterpret_cast< wchar_t* >( entry->BaseDllName.Buffer ), info->module ) == 0 ) {
					info->response = reinterpret_cast< ULONG64 >( entry->DllBase );

					break;
				}
			}
		}

		irp->IoStatus.Information = sizeof( BASE_ADDRESS_CALLBACK_INPUT );

		break;
	}

	case IOCTL_UNLOAD: {
		UNICODE_STRING dos_devices_link_name = RTL_CONSTANT_STRING( L"\\DosDevices\\hotwheels" );

		if ( !NT_SUCCESS( delete_symbolic_link( &dos_devices_link_name ) ) ) {
			dbg_print( "[hotwheels] [!delete_symbolic_link!] " );
		}

		delete_device( device_object );
		delete_driver( g_driver_object );

		dbg_print( "[hotwheels] Successfully unloaded driver. " );

		break;
	}
	}

	IoCompleteRequest( irp, IO_NO_INCREMENT );

	return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS protect_processes_callback( PVOID registration_context, POB_PRE_OPERATION_INFORMATION pre_operation_info )
{
	UNREFERENCED_PARAMETER( registration_context );
	UNREFERENCED_PARAMETER( pre_operation_info );

	return OB_PREOP_SUCCESS;
}

NTSTATUS create_ioctl_device( PDRIVER_OBJECT driver_object )
{
	PDEVICE_OBJECT device{ };
	UNICODE_STRING device_name = RTL_CONSTANT_STRING( L"\\Device\\hotwheels" );

	NTSTATUS create_device_return = create_device( driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device );

	if ( !device || !NT_SUCCESS( create_device_return ) ) {
		dbg_print( "[hotwheels] [!create_device!] %ul.", create_device_return );

		return STATUS_FAIL_CHECK;
	}

	dbg_print( "[hotwheels] Created IOCTL device. 0x%x", device );

	UNICODE_STRING dos_devices_link_name = RTL_CONSTANT_STRING( L"\\DosDevices\\hotwheels" );
	NTSTATUS create_symbolic_link_return = create_symbolic_link( &dos_devices_link_name, &device_name );

	if ( !NT_SUCCESS( create_symbolic_link_return ) ) {
		dbg_print( "[hotwheels] [!create_symbolic_link!] %ul.", create_symbolic_link_return );

		return STATUS_FAIL_CHECK;
	}

	dbg_print( "[hotwheels] Created Symbolic Link. 0x%x", device );

	// HACK: Windows say to do this in device_create, which is much more safe.
	ClearFlag( device->Flags, DO_DEVICE_INITIALIZING );

	device->Flags |= DO_DIRECT_IO;

	driver_object->MajorFunction[ IRP_MJ_CREATE ]         = device_create_callback;
	driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = device_control_callback;

	return STATUS_SUCCESS;
}

NTSTATUS driver_entry( PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path )
{
	UNREFERENCED_PARAMETER( reg_path );

	g_driver_object = driver_object;

	NTSTATUS return_code = create_ioctl_device( driver_object );

	if ( !NT_SUCCESS( return_code ) ) {
		dbg_print( "[hotwheels] [!create_ioctl_device!] %ul", return_code );

		return STATUS_ABANDONED;
	}

	dbg_print( "[hotwheels] Driver initialized.", return_code );

	return STATUS_SUCCESS;
}

NTSTATUS mm_driver_entry( PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path )
{
	UNREFERENCED_PARAMETER( driver_object );
	UNREFERENCED_PARAMETER( reg_path );

	WCHAR driver_name_[] = { L'\\', L'D', L'r', L'i', L'v', L'e', 'r', '\\', L'\0', L'\0', L'\0', L'\0', L'\0', L'\0', L'\0' };
	WCHAR dictionary[]   = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	LARGE_INTEGER time{ };

	query_system_time_precise( &time );

	driver_name_[ 8 ]  = dictionary[ random( &time.LowPart ) % sizeof( dictionary ) / sizeof( WCHAR ) ];
	driver_name_[ 9 ]  = dictionary[ random( &time.LowPart ) % sizeof( dictionary ) / sizeof( WCHAR ) ];
	driver_name_[ 10 ] = dictionary[ random( &time.LowPart ) % sizeof( dictionary ) / sizeof( WCHAR ) ];
	driver_name_[ 11 ] = dictionary[ random( &time.LowPart ) % sizeof( dictionary ) / sizeof( WCHAR ) ];
	driver_name_[ 12 ] = dictionary[ random( &time.LowPart ) % sizeof( dictionary ) / sizeof( WCHAR ) ];
	driver_name_[ 13 ] = dictionary[ random( &time.LowPart ) % sizeof( dictionary ) / sizeof( WCHAR ) ];

	UNICODE_STRING driver_name = RTL_CONSTANT_STRING( driver_name_ );
	UNICODE_STRING device_name = RTL_CONSTANT_STRING( L"\\Device\\hotwheels" );

	PDEVICE_OBJECT device_handle{ };
	PFILE_OBJECT file_handle{ };

	if ( NT_SUCCESS( get_device_object_pointer( &device_name, GENERIC_READ | GENERIC_WRITE, &file_handle, &device_handle ) ) ) {
		ULONG_PTR information{ };

		if ( !NT_SUCCESS( device_io_control( device_handle, IOCTL_UNLOAD, 0x0, nullptr, 0x0, nullptr, 0x0, &information ) ) ) {
			dbg_print( "[hotwheels] [!device_io_control!] " );
		}
	}

	if ( NT_SUCCESS( create_driver( &driver_name, &driver_entry ) ) ) {
		return STATUS_SUCCESS;
	}

	return STATUS_ABANDONED;
}
