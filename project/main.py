import ctypes
import psutil
from ctypes import wintypes

from constants.win_constants import *
from constants.win_structs import *

# Constants from the Windows API
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Define necessary types
HANDLE = wintypes.HANDLE
LPVOID = ctypes.c_void_p

# Load required DLLs
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

# Define necessary functions from the DLLs
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = wintypes.BOOL

GetProcessMemoryInfo = psapi.GetProcessMemoryInfo
GetProcessMemoryInfo.argtypes = [
    HANDLE,
    ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
    wintypes.DWORD,
]
GetProcessMemoryInfo.restype = wintypes.BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    HANDLE,
    LPVOID,
    LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = wintypes.BOOL


def get_process_handle(process_id):
    desired_access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = OpenProcess(desired_access, False, process_id)
    if not handle:
        raise ValueError(f"Failed to open process (ID: {process_id})")
    return handle


def get_process_info(process_handle):
    process_memory_info = PROCESS_MEMORY_COUNTERS()
    GetProcessMemoryInfo(
        process_handle,
        ctypes.byref(process_memory_info),
        ctypes.sizeof(process_memory_info),
    )
    return process_memory_info


def search_memory_pattern(handle, pattern):
    system_info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(system_info))
    page_size = system_info.dwPageSize

    memory_basic_information = MEMORY_BASIC_INFORMATION()
    address = LPVOID(0)

    while (
        kernel32.VirtualQueryEx(
            handle,
            address,
            ctypes.byref(memory_basic_information),
            ctypes.sizeof(memory_basic_information),
        )
        != 0
    ):
        if (
            memory_basic_information.State == 0x1000
            and memory_basic_information.Protect == 0x40
        ):
            buffer_size = (
                ctypes.sizeof(ctypes.c_char) * memory_basic_information.RegionSize
            )
            buffer = ctypes.create_string_buffer(buffer_size)
            bytes_read = ctypes.c_size_t(0)

            if ReadProcessMemory(
                handle,
                memory_basic_information.BaseAddress,
                buffer,
                ctypes.sizeof(buffer),
                ctypes.byref(bytes_read),
            ):
                # Search for the pattern in the buffer
                if pattern in buffer.raw[: bytes_read.value]:
                    print(
                        f"Pattern found at address: 0x{memory_basic_information.BaseAddress:X}"
                    )

        if memory_basic_information.BaseAddress is None:
            break

        address = LPVOID(
            ctypes.addressof(memory_basic_information.BaseAddress.contents)
            + memory_basic_information.RegionSize
        )


if __name__ == "__main__":
    processes = psutil.process_iter()

    for process in processes:
        process_name = process.name()
        process_id = process.pid
        print(f"Process Name: {process_name}, Process ID: {process_id}")

    print("Input desired process PID:")
    process_pid = int(input("#>"))

    try:
        handle = get_process_handle(process_pid)
        print(f"Process handle: {handle}")

        # Get process information
        process_info = get_process_info(handle)
        print("-----Process Info-----")
        print(f"Page Fault Count: {process_info.PageFaultCount}")
        print(f"Working Set Size: {process_info.WorkingSetSize}")
        print(f"Peak Working Set Size: {process_info.PeakWorkingSetSize}")
        print(f"Pagefile Usage: {process_info.PagefileUsage}")
        print(f"Peak Pagefile Usage: {process_info.PeakPagefileUsage}")

        print("-----Memory Credential Dump-----")
        # Search memory for a specific pattern
        pattern_to_search = (
            b"\x41\x42\x43"  # Replace with the actual pattern to search (as bytes)
        )
        search_memory_pattern(handle, pattern_to_search)

    except ValueError as e:
        print(f"Error: {str(e)}")
    finally:
        if handle is not None:
            CloseHandle(handle)
