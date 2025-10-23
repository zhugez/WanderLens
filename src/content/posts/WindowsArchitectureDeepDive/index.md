---
title: "Windows Architecture Deep Dive: User Mode vs Kernel Mode"
published: 2025-09-15
description: "Deep dive vào kiến trúc Windows - phân tích ranh giới giữa User Mode và Kernel Mode, cơ chế system call, và ứng dụng trong offensive security research."
image: ""
tags: ["windows", "kernel-mode", "system-calls"]
category: "Cybersecurity"
draft: true
lang: "en"
---

## Giới thiệu

Hiểu rõ Windows architecture là nền tảng quan trọng nhất cho bất kỳ ai làm offensive security research targeting Windows systems. Cho dù bạn đang develop exploits, phân tích malware, hay research vulnerabilities, kiến thức sâu về cách Windows hoạt động ở mức architectural là absolutely essential.

Bài này deep dive vào ranh giới giữa **User Mode** và **Kernel Mode** - boundary định nghĩa privilege levels, memory isolation, và system call interface kết nối hai thế giới này.

### Tại sao điều này quan trọng?

**Đối với Exploit Development:**
- Hiểu syscalls → bypass user-mode hooks
- Biết về privilege transitions → identify attack surfaces
- Nắm memory architecture → reliable exploitation

**Đối với Malware Development:**
- Direct syscalls → bypass EDR/AV monitoring
- Kernel knowledge → develop rootkits
- System internals → better evasion

**Đối với Vulnerability Research:**
- Boundary crossings → attack surfaces
- Kernel objects → privilege escalation vectors
- IRP handling → driver vulnerabilities

---

## Windows Architecture Overview

Windows sử dụng **layered architecture** với sự phân tách rõ ràng giữa privileged và unprivileged code. Design này cung cấp security thông qua isolation nhưng vẫn maintain performance qua efficient privilege transitions.

```
┌─────────────────────────────────────────────────────┐
│           USER MODE (Ring 3)                        │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │ Applications │  │   Subsystem  │  │   DLLs   │ │
│  │   (*.exe)    │  │   DLLs       │  │          │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
│         │                  │                │      │
│         └──────────────────┴────────────────┘      │
│                        │                            │
│              ┌─────────▼─────────┐                 │
│              │   Windows API     │                 │
│              │  (kernel32.dll)   │                 │
│              └─────────┬─────────┘                 │
│                        │                            │
│              ┌─────────▼─────────┐                 │
│              │   Native API      │                 │
│              │   (ntdll.dll)     │                 │
│              └─────────┬─────────┘                 │
└────────────────────────┼─────────────────────────────┘
                         │ SYSCALL/SYSENTER
═══════════════════════════════════════════════════════
                         │
┌────────────────────────▼─────────────────────────────┐
│           KERNEL MODE (Ring 0)                      │
│                                                     │
│  ┌─────────────────────────────────────────────┐  │
│  │   System Service Dispatcher (KiSystemCall)  │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                               │
│  ┌─────────────────▼───────────────────────────┐  │
│  │        Executive Services                   │  │
│  │  (I/O Manager, Object Manager, Memory Mgr)  │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                               │
│  ┌─────────────────▼───────────────────────────┐  │
│  │        Windows Kernel (ntoskrnl.exe)        │  │
│  │     (Scheduler, Dispatcher, Sync Objects)   │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                               │
│  ┌─────────────────▼───────────────────────────┐  │
│  │   Hardware Abstraction Layer (hal.dll)      │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                               │
│  ┌─────────────────▼───────────────────────────┐  │
│  │          Device Drivers                     │  │
│  └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                     │
              ┌──────▼──────┐
              │  Hardware   │
              └─────────────┘
```

---

## User Mode (Ring 3)

User mode là **restricted execution environment** nơi tất cả application code chạy. Nó operate ở **Processor Ring 3** (least privileged ring trong x86/x64 architecture).

### Đặc điểm chính:

**Limited Privileges:**
- Không thể directly access hardware
- Không thể execute privileged instructions
- Không thể directly modify kernel memory
- Không thể disable interrupts

**Memory Isolation:**
- Mỗi process có virtual address space riêng
- Processes không thể directly access memory của nhau
- User-mode addresses: `0x0000000000000000` - `0x00007FFFFFFFFFFF` (x64)

**Components chạy trong User Mode:**
- User applications (*.exe)
- System processes (csrss.exe, services.exe, etc.)
- Subsystem DLLs (kernel32.dll, user32.dll, etc.)
- Native API layer (ntdll.dll)

### Tại sao User Mode Isolation quan trọng?

Isolation này là **first line of defense** chống lại:
- Malicious applications phá hỏng system
- Buggy code gây system-wide crashes
- Unauthorized access vào sensitive kernel structures

Tuy nhiên, isolation này cũng là cái mà **security researchers target** thông qua:
- Privilege escalation exploits
- Kernel vulnerabilities
- Driver exploitation

---

## Kernel Mode (Ring 0)

Kernel mode là **fully privileged execution environment** nơi operating system core chạy. Nó operate ở **Processor Ring 0** (most privileged ring).

### Đặc điểm chính:

**Full System Access:**
- Direct hardware access
- Execution của privileged instructions (e.g., `lgdt`, `lidt`, `mov cr3`)
- Complete memory access (user + kernel space)
- Interrupt và exception handling

**Memory Layout:**
- Kernel addresses: `0xFFFF800000000000` - `0xFFFFFFFFFFFFFFFF` (x64)
- Tất cả kernel-mode components share cùng address space
- Direct access vào physical memory qua page tables

**Components chạy trong Kernel Mode:**
- Windows Kernel (ntoskrnl.exe)
- Hardware Abstraction Layer (hal.dll)
- Device Drivers (*.sys)
- Kernel-mode components (win32k.sys, etc.)

### Power và Danger của Kernel Mode

**Power:**
- Complete system control
- Optimal performance (no context switches)
- Direct hardware manipulation

**Danger:**
- Một bug duy nhất có thể crash toàn bộ system (BSOD)
- Exploits gain complete system compromise
- Không có isolation giữa kernel components

Đây là lý do **kernel exploitation là holy grail** của offensive security - một vulnerability duy nhất trong kernel mode grants absolute control over the system.

---

## System Call Interface

**System call** mechanism là controlled gateway giữa user mode và kernel mode. Đây là cách hợp pháp duy nhất để user-mode code request kernel services.

### System Call Flow

Hãy trace một `CreateFile` call đơn giản qua toàn bộ system:

```c
// 1. Application calls Win32 API
HANDLE hFile = CreateFile(
    L"C:\\test.txt",
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);
```

**Step 1: Win32 API (kernel32.dll)**

```asm
; kernel32!CreateFileW
; Validates parameters và converts sang Native API
call    qword ptr [kernel32!_imp_NtCreateFile]
```

**Step 2: Native API (ntdll.dll)**

```asm
; ntdll!NtCreateFile
mov     r10, rcx              ; Save RCX
mov     eax, 0x55             ; Syscall number cho NtCreateFile
syscall                        ; Transition sang kernel mode
ret
```

**Step 3: Kernel Mode Transition**

Khi `syscall` instruction executes:

1. **CPU switches sang Ring 0**
2. **RSP switches** sang kernel stack
3. **RIP jumps** vào `KiSystemCall64` trong ntoskrnl.exe
4. **Saves user-mode context** (registers, stack pointer)

**Step 4: System Service Dispatcher**

```asm
; KiSystemCall64
; RAX contains syscall number (0x55)
; Lookup trong System Service Descriptor Table (SSDT)
mov     rax, [nt!KeServiceDescriptorTable + rax*8]
call    rax                   ; Call NtCreateFile trong kernel
```

**Step 5: Kernel Execution**

```c
// nt!NtCreateFile (simplified)
NTSTATUS NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    // Validate parameters từ user mode
    ProbeForWrite(FileHandle, sizeof(HANDLE), sizeof(HANDLE));

    // Call I/O Manager
    IoCreateFile(...);

    // Return status
    return STATUS_SUCCESS;
}
```

**Step 6: Return về User Mode**

- Kernel function returns NTSTATUS
- `KiSystemCallExit` restores user-mode context
- CPU switches back về Ring 3
- Execution continues trong ntdll.dll

---

## System Call Numbers

Mỗi kernel function có unique **syscall number** (còn gọi là system service number). Những numbers này:

- **Version-specific** (change between Windows versions)
- **Architecture-specific** (different cho x86 vs x64)
- **Undocumented** by Microsoft

### Ví dụ Syscall Numbers (Windows 11 23H2 x64)

| Function | Syscall Number |
|----------|----------------|
| NtCreateFile | 0x55 |
| NtReadFile | 0x06 |
| NtWriteFile | 0x08 |
| NtOpenProcess | 0x26 |
| NtAllocateVirtualMemory | 0x18 |
| NtProtectVirtualMemory | 0x50 |

### Tại sao Syscall Numbers quan trọng?

**Cho Offensive Research:**
- **Direct syscalls** bypass user-mode hooks (EDR/AV)
- **Hell's Gate** technique dynamically resolves syscall numbers
- Understanding SSDT giúp trong kernel exploitation

**Practical Implication:**
Hầu hết EDR/AV solutions hook user-mode APIs (kernel32.dll, ntdll.dll). Bằng cách call syscalls directly, malware có thể evade những hooks này hoàn toàn.

---

## Processor Rings và Privilege Levels

Architecture x86/x64 định nghĩa **4 privilege rings** (Ring 0-3), nhưng Windows chỉ dùng hai:

```
┌─────────────────────────────────────┐
│         Ring 0 (Kernel Mode)        │
│   Highest Privilege - Full Access   │
│                                     │
│  ┌─────────────────────────────┐   │
│  │   Ring 1 (Unused)           │   │
│  │                             │   │
│  │  ┌─────────────────────┐   │   │
│  │  │ Ring 2 (Unused)     │   │   │
│  │  │                     │   │   │
│  │  │  ┌─────────────┐   │   │   │
│  │  │  │   Ring 3    │   │   │   │
│  │  │  │ (User Mode) │   │   │   │
│  │  │  │  Lowest     │   │   │   │
│  │  │  │  Privilege  │   │   │   │
│  │  │  └─────────────┘   │   │   │
│  │  └─────────────────────┘   │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

**Current Privilege Level (CPL)** được stored trong CS register:
- **CPL = 0**: Kernel mode
- **CPL = 3**: User mode

### Privilege Checks

CPU automatically enforces privilege checks:

```c
// Attempting to execute privileged instruction trong user mode
// Sẽ cause #GP (General Protection Fault)

__asm {
    cli    // Clear Interrupt Flag - privileged instruction
}
// Result: Exception 0x0D (EXCEPTION_PRIVILEGED_INSTRUCTION)
```

---

## Syscall Instruction Deep Dive (x64)

Modern 64-bit Windows sử dụng **SYSCALL/SYSRET** instruction pair cho fast system calls, thay thế slower `int 0x2E` mechanism.

### SYSCALL Mechanism

**MSR Registers (Model-Specific Registers):**

```
IA32_LSTAR   (0xC0000082): Entry point (KiSystemCall64)
IA32_STAR    (0xC0000081): Code segment selectors
IA32_FMASK   (0xC0000084): RFLAGS mask
IA32_KERNEL_GS_BASE (0xC0000102): Kernel GS base
```

**Khi SYSCALL executes:**

1. `RCX ← RIP` (save return address)
2. `R11 ← RFLAGS` (save flags)
3. `RIP ← IA32_LSTAR` (jump vào `KiSystemCall64`)
4. `CS ← IA32_STAR[47:32]` (load kernel code segment)
5. `SS ← IA32_STAR[47:32] + 8` (load kernel stack segment)
6. `CPL ← 0` (switch sang Ring 0)
7. `RFLAGS ← RFLAGS & ~IA32_FMASK` (mask flags)

### SYSRET Return Mechanism

```asm
; Return từ kernel về user mode
sysret
```

**Khi SYSRET executes:**

1. `RIP ← RCX` (restore return address)
2. `RFLAGS ← R11` (restore flags)
3. `CS ← IA32_STAR[63:48] + 16` (restore user code segment)
4. `SS ← IA32_STAR[63:48] + 8` (restore user stack segment)
5. `CPL ← 3` (switch về Ring 3)

---

## Practical Implications cho Security Research

### 1. Direct Syscalls để EDR Evasion

Hầu hết EDR/AV products hook user-mode APIs. Bằng cách invoke syscalls directly, bạn có thể bypass những hooks này:

```c
// Traditional approach (hooked bởi EDR)
#include <windows.h>

HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

// Direct syscall approach (bypasses hooks)
typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

// Manually craft syscall stub
__asm {
    mov r10, rcx
    mov eax, 0x26        // NtOpenProcess syscall number
    syscall
    ret
}
```

**Techniques:**
- **Hell's Gate**: Dynamically resolve syscall numbers từ ntdll.dll
- **Halo's Gate**: Handle hooked syscalls bằng cách tìm nearby clean stubs
- **SysWhispers**: Pre-generate syscall stubs cho all Windows versions

### 2. Understanding Kernel Entry Points

Biết kernel entry mechanism giúp trong:

**Exploit Development:**
- Kernel shellcode phải restore proper state trước khi return
- Understanding `KPCR` (Kernel Processor Control Region) structure
- Proper syscall number usage trong exploits

**Rootkit Development:**
- Hooking `KiSystemCall64` cho system-wide API monitoring
- SSDT hooking (System Service Descriptor Table)
- IDT hooking cho interrupt interception

### 3. Memory Layout Implications

Memory split có consequences quan trọng:

**64-bit Windows (x64):**
```
User Space:   0x0000000000000000 - 0x00007FFFFFFFFFFF (128 TB)
Kernel Space: 0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF (128 TB)
```

**Cho Exploitation:**
- User-mode pointers phải được validated trong kernel (ProbeForRead/ProbeForWrite)
- Failure to validate = arbitrary kernel write vulnerability
- SMEP (Supervisor Mode Execution Prevention) prevents executing user-mode code từ kernel context

---

## Lab Exercise: Tracing System Calls với WinDbg

Hãy perform một practical exercise để observe system calls in action.

### Setup Requirements

1. **Windows 11 VM** (target machine)
2. **WinDbg Preview** (debugger trên host)
3. **Kernel debugging enabled** trên VM

### Enable Kernel Debugging

```powershell
# Trên target VM (Administrator)
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
shutdown /r /t 0
```

### Exercise 1: View System Call in Action

**Step 1: Break into kernel debugger**

```
Debug → Break (Ctrl+Break)
```

**Step 2: Set breakpoint trên NtCreateFile**

```
kd> bp nt!NtCreateFile
kd> g
```

**Step 3: Trên target VM, create một file**

```powershell
# Trên target VM
notepad.exe
# File → Save → Type filename → Click Save
```

**Step 4: Khi breakpoint hits, examine call stack**

```
kd> k
# 0 nt!NtCreateFile
# 1 nt!KiSystemCall64Shadow
# 2 nt!KiSystemCall64
# 3 ntdll!NtCreateFile + 0x14
# 4 kernelbase!CreateFileW + 0x66
# 5 notepad!SaveFile + 0x1a2
```

**Step 5: Examine syscall number trong RAX**

```
kd> r rax
rax=0000000000000055    # NtCreateFile syscall number
```

**Step 6: View parameters**

```
kd> dq @rcx L1    # FileHandle
kd> dq @rdx L1    # DesiredAccess
kd> dt nt!_OBJECT_ATTRIBUTES @r8    # ObjectAttributes
```

### Exercise 2: Enumerate All Syscalls

**View SSDT (System Service Descriptor Table):**

```
kd> dq nt!KeServiceDescriptorTable L2
# fffff800`12345678  fffff800`12abc000   # ServiceTableBase
# fffff800`12345680  0000000000000000   # ServiceCounterTableBase
```

**Resolve syscall numbers sang function names:**

```
kd> !reload
kd> dps nt!KiServiceTable L4
# fffff800`12abc000  nt!NtAccessCheck
# fffff800`12abc008  nt!NtWorkerFactoryWorkerReady
# fffff800`12abc010  nt!NtAcceptConnectPort
# fffff800`12abc018  nt!NtMapUserPhysicalPagesScatter
```

---

## Modern Mitigations

### SMEP (Supervisor Mode Execution Prevention)

Được giới thiệu trong Windows 8, SMEP prevents kernel từ việc executing user-mode code:

```
CR4 register bit 20 = 1 → SMEP enabled
```

**Impact trên Exploitation:**
- Kernel exploits không thể simply jump vào shellcode trong user-mode
- Requires ROP (Return-Oriented Programming) trong kernel space
- Hoặc disabling SMEP (requires arbitrary write vào CR4)

### SMAP (Supervisor Mode Access Prevention)

Được giới thiệu trong Windows 10 RS3, SMAP prevents kernel từ việc accessing user-mode memory:

```
CR4 register bit 21 = 1 → SMAP enabled
```

**Impact trên Exploitation:**
- Kernel không thể dereference user-mode pointers without explicit override
- Requires sử dụng ProbeForRead/ProbeForWrite APIs
- More careful exploit primitive construction

### HVCI (Hypervisor-Protected Code Integrity)

Còn được gọi là Memory Integrity, sử dụng virtualization để protect kernel code:

- Kernel code pages được marked read-only via hypervisor EPT (Extended Page Tables)
- Attempts to modify kernel code trigger VM exits
- Defeats hầu hết traditional kernel hooking techniques

> **Note:** HVCI là một trong những mitigations mạnh nhất của Windows hiện đại. Nó leverage hardware virtualization (VT-x/AMD-V) để create một trusted execution environment. Understanding HVCI là critical cho modern kernel exploit development.

---

## Common Misconceptions

### Misconception 1: "Syscalls chậm"

**Reality:** Modern `syscall` instruction cực kỳ fast (~50-100 CPU cycles). Overhead đến từ:
- Parameter validation
- Context saving/restoring
- Actual kernel work được performed

### Misconception 2: "Tất cả kernel functions start với Nt"

**Reality:**
- `Nt*` functions là native API exported bởi ntoskrnl.exe
- `Zw*` versions giống hệt nhưng perform previous mode checks
- Internal kernel functions dùng various prefixes (Ke, Mm, Io, etc.)

### Misconception 3: "Direct syscalls luôn bypass EDR"

**Reality:** Modern EDRs có thể detect direct syscalls thông qua:
- Call stack analysis (missing ntdll.dll frames)
- Syscall origin checks (executing từ unusual memory)
- Behavioral detection (suspicious API patterns)

---

## Wrapup

Understanding Windows architecture - đặc biệt là user/kernel mode boundary và system call mechanism - là fundamental cho tất cả advanced Windows security research. Knowledge này forms nền tảng cho:

- **Exploit development**: Understanding privilege boundaries và attack surfaces
- **Malware development**: Implementing evasion thông qua direct syscalls
- **Vulnerability research**: Identifying weaknesses trong syscall interface
- **Reverse engineering**: Comprehending system behavior ở lowest level

Knowledge về Windows architecture này là foundation cho advanced exploitation techniques, malware development, và vulnerability research.

---

## References

**Books:**
- **Windows Internals, Part 1 & 2** (7th Edition) - Mark Russinovich, David Solomon, Alex Ionescu
- **Windows Kernel Programming** - Pavel Yosifovich
- **Rootkits and Bootkits** - Alex Matrosov, Eugene Rodionov, Sergey Bratus

**Microsoft Documentation:**
- [Windows kernel-mode driver architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)
- [System Service Descriptor Table](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/system-service-descriptor-table)

**Tools:**
- [SysWhispers](https://github.com/jthuraisamy/SysWhispers) - Syscall generation framework
- [System Informer](https://github.com/winsiderss/systeminformer) - System exploration tool
- [WinDbg Preview](https://apps.microsoft.com/detail/9PGJGD53TN86) - Modern Windows debugger

---

<h2><strong style="color: red;">Master the fundamentals, exploit the system.</strong></h2>
