#pragma once
#include <ntdef.h>
#include <ntstatus.h>
#include <windows.h>

#define populatePrototype(x, dll) x x##F = (x)GetProcAddress(dll, #x)

// 0x10 bytes (sizeof)
typedef struct _CLIENT_ID {
  VOID *UniqueProcess; // 0x0
  VOID *UniqueThread;  // 0x8
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE {
  ULONG_PTR Attribute;
  SIZE_T Size;
  union {
    ULONG_PTR Value;
    PVOID ValuePtr;
  };
  PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
  SIZE_T TotalLength;
  PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// Function prototypes
typedef NTSTATUS(NTAPI *NtOpenProcess)(_Out_ PHANDLE processHandle,
                                       _In_ ACCESS_MASK desiredAccess,
                                       _In_ POBJECT_ATTRIBUTES objectAttributes,
                                       _In_opt_ PCLIENT_ID clientId);

typedef NTSTATUS(NTAPI *NtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
    _In_ LPVOID StartRoutine, _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits, _In_ SIZE_T StackSize, _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress,
                 _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize)
                     _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType, _In_ ULONG PageProtection);
;

typedef NTSTATUS(NTAPI *NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite, _Out_opt_ PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI *NtClose)(_In_ HANDLE Handle);
