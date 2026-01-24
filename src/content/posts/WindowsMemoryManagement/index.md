---
title: "Windows Memory Management Internals: Virtual Memory, Page Tables & Exploitation"
published: 2025-09-28
description: "Deep dive vào Windows memory management - virtual memory architecture, page tables, VAD trees, và practical implications cho kernel exploitation."
image: ""
tags: ["windows", "memory-management", "kernel-exploitation"]
category: "Cybersecurity"
draft: false
lang: "en"
---

## Giới thiệu

Memory management là một trong những components phức tạp nhất của Windows kernel. Understanding memory internals không chỉ critical cho exploit development mà còn essential cho malware analysis, rootkit development, và vulnerability research.

Bài này deep dive vào Windows memory management architecture - từ virtual memory layout, page table structures, đến VAD trees và physical memory management. Chúng ta sẽ focus vào practical implications cho security research và exploitation.

### Tại sao Memory Management quan trọng?

**Đối với Exploit Development:**
- Understanding page tables → craft reliable exploits
- VAD enumeration → find executable memory regions
- Pool spraying → heap exploitation techniques
- Memory corruption bugs thường liên quan đến memory management

**Đối với Malware/Rootkit Development:**
- Hiding memory regions
- Manipulating VAD structures
- Pool tags để avoid detection
- Direct physical memory access

**Đối với Vulnerability Research:**
- Memory corruption vulnerabilities
- Use-after-free conditions
- Pool overflow bugs
- Type confusion trong kernel objects

---

## Virtual Memory Architecture

Windows sử dụng **virtual memory system** để provide mỗi process một isolated address space. Trên x64 Windows, address space được chia làm hai phần:

```
┌─────────────────────────────────────────────────────┐
│         64-bit Address Space (x64)                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  User Space (Ring 3)                                │
│  0x0000000000000000 - 0x00007FFFFFFFFFFF            │
│  Size: 128 TB                                       │
│                                                     │
│  ┌────────────────────────────────────────────┐    │
│  │  Process Private Memory                    │    │
│  │  - Executable Image (PE)                   │    │
│  │  - DLLs                                    │    │
│  │  - Heap                                    │    │
│  │  - Stack                                   │    │
│  │  - Thread Stacks                          │    │
│  └────────────────────────────────────────────┘    │
│                                                     │
├═════════════════════════════════════════════════════┤
│         Non-canonical Address Space                 │
│  0x0000800000000000 - 0xFFFF7FFFFFFFFFFF            │
│  (Invalid - causes access violation)                │
├═════════════════════════════════════════════════════┤
│                                                     │
│  Kernel Space (Ring 0)                              │
│  0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF            │
│  Size: 128 TB                                       │
│                                                     │
│  ┌────────────────────────────────────────────┐    │
│  │  System Memory                             │    │
│  │  - Kernel Image (ntoskrnl.exe)            │    │
│  │  - HAL (hal.dll)                          │    │
│  │  - Drivers (*.sys)                        │    │
│  │  - Paged Pool                             │    │
│  │  - Non-Paged Pool                         │    │
│  │  - System Cache                           │    │
│  │  - PFN Database                           │    │
│  └────────────────────────────────────────────┘    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Key Regions trong Kernel Space

**System PTEs (Page Table Entries):**
- Virtual addresses cho mapping I/O space
- Dynamic mapping của physical memory
- Used bởi drivers cho DMA operations

**Paged Pool:**
- Pageable kernel memory
- Có thể được paged out vào disk
- Used cho less critical allocations
- Size: ~300 MB - 600 MB (tuỳ RAM)

**Non-Paged Pool:**
- Always resident trong RAM
- Cannot be paged out
- Used cho critical kernel structures (spinlocks, DPCs, etc.)
- Size: ~75 MB - 300 MB

**PFN Database:**
- Tracks tất cả physical memory pages
- One entry per physical page
- Size depends on RAM amount
- Critical cho memory management operations

> **Note:** Trên Windows 10+, **memory compression** được enabled by default. Thay vì page memory ra disk, Windows compress pages trong RAM để save space. Điều này làm thay đổi behavior của paging và có implications cho memory forensics.

---

## Page Table Structure (4-Level Paging)

Windows x64 sử dụng **4-level page table hierarchy** để translate virtual addresses sang physical addresses. Understanding structure này là essential cho memory exploitation.

### 4-Level Paging Hierarchy

```
Virtual Address (64-bit)
┌──────┬──────┬──────┬──────┬──────────────┐
│ Sign │ PML4 │ PDPT │  PD  │  PT  │ Offset│
│ Ext  │Index │Index │Index │Index │       │
├──────┼──────┼──────┼──────┼──────┼───────┤
│16 bit│ 9bit │ 9bit │ 9bit │ 9bit │12 bit │
└──────┴──────┴──────┴──────┴──────┴───────┘
  63-48  47-39  38-30  29-21  20-12   11-0

Translation Process:
┌─────────────────────────────────────────────┐
│  CR3 Register (Physical Address)            │
│  Points to PML4 Table                       │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  PML4 (Page Map Level 4)                    │
│  512 entries (PML4E)                        │
│  Each entry covers 512 GB                   │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  PDPT (Page Directory Pointer Table)        │
│  512 entries (PDPTE)                        │
│  Each entry covers 1 GB                     │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  PD (Page Directory)                        │
│  512 entries (PDE)                          │
│  Each entry covers 2 MB                     │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  PT (Page Table)                            │
│  512 entries (PTE)                          │
│  Each entry covers 4 KB                     │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  Physical Page (4 KB)                       │
│  Actual data location trong RAM             │
└─────────────────────────────────────────────┘
```

### Page Table Entry (PTE) Structure

Mỗi PTE là 64-bit value chứa thông tin về page:

```c
typedef struct _MMPTE_HARDWARE {
    ULONGLONG Valid              : 1;   // Bit 0:  Page is present
    ULONGLONG Write              : 1;   // Bit 1:  Page is writable
    ULONGLONG Owner              : 1;   // Bit 2:  User/Supervisor (0=kernel, 1=user)
    ULONGLONG WriteThrough       : 1;   // Bit 3:  Write-through caching
    ULONGLONG CacheDisable       : 1;   // Bit 4:  Cache disabled
    ULONGLONG Accessed           : 1;   // Bit 5:  Page has been accessed
    ULONGLONG Dirty              : 1;   // Bit 6:  Page has been written to
    ULONGLONG LargePage          : 1;   // Bit 7:  Large page (2MB/1GB)
    ULONGLONG Global             : 1;   // Bit 8:  Global page (TLB)
    ULONGLONG CopyOnWrite        : 1;   // Bit 9:  Copy-on-write
    ULONGLONG Prototype          : 1;   // Bit 10: Prototype PTE
    ULONGLONG Reserved           : 1;   // Bit 11: Reserved
    ULONGLONG PageFrameNumber    : 36;  // Bits 12-47: Physical page number
    ULONGLONG Reserved1          : 4;   // Bits 48-51: Reserved
    ULONGLONG SoftwareWsIndex    : 11;  // Bits 52-62: Software field
    ULONGLONG NoExecute          : 1;   // Bit 63: NX bit (No Execute)
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;
```

### Important PTE Bits cho Security

**Valid Bit (Bit 0):**
- 0 = Page not present trong RAM (page fault khi access)
- 1 = Page is present

**Write Bit (Bit 1):**
- 0 = Read-only page
- 1 = Writable page
- Exploits thường target việc flip bit này

**Owner Bit (Bit 2):**
- 0 = Supervisor (kernel mode only)
- 1 = User (accessible from user mode)
- **SMEP** enforces execution restrictions dựa trên bit này

**NoExecute Bit (Bit 63):**
- 0 = Executable page
- 1 = Non-executable (NX/DEP enabled)
- **DEP** dựa vào bit này để prevent code execution

---

## Virtual Address Translation Example

Hãy walk through một virtual address translation manually:

### Example: Translate `0xFFFFF80012345678`

**Step 1: Parse virtual address**

```
Address: 0xFFFFF80012345678

Binary:
1111 1111 1111 1111 1111 1000 0000 0000 0001 0010 0011 0100 0101 0110 0111 1000

Parse:
Sign Extension: 1111 1111 1111 1111 (bits 63-48)
PML4 Index:     1 1111 1000 (0x1F8 = 504)
PDPT Index:     0 0000 0000 (0x000 = 0)
PD Index:       0 0000 0010 (0x002 = 2)
PT Index:       0 1001 1010 (0x09A = 154)
Offset:         0101 0110 0111 1000 (0x578)
```

**Step 2: Walk page tables**

```
1. Read CR3 → PML4 base address: 0x1A5000

2. PML4[504] lookup:
   Address = 0x1A5000 + (504 * 8) = 0x1A5FC0
   Read PML4E → PDPT base: 0x2B6000

3. PDPT[0] lookup:
   Address = 0x2B6000 + (0 * 8) = 0x2B6000
   Read PDPTE → PD base: 0x3C7000

4. PD[2] lookup:
   Address = 0x3C7000 + (2 * 8) = 0x3C7010
   Read PDE → PT base: 0x4D8000

5. PT[154] lookup:
   Address = 0x4D8000 + (154 * 8) = 0x4D84D0
   Read PTE → Physical page: 0x5E9000

6. Final physical address:
   Physical = 0x5E9000 + 0x578 = 0x5E9578
```

**Step 3: Examine PTE bits**

```
PTE Value: 0x0000000005E9867
Binary:   0000 ... 0101 1110 1001 1000 0110 0111

Bits:
- Valid:     1 (page present)
- Write:     1 (writable)
- Owner:     1 (user accessible)
- Accessed:  1 (has been accessed)
- Dirty:     0 (not modified)
- NX:        0 (executable)
```

---

## VAD (Virtual Address Descriptor) Trees

**VAD trees** track tất cả virtual memory allocations trong một process. Mỗi process có một VAD tree trong `EPROCESS` structure.

### VAD Structure

```c
typedef struct _MMVAD {
    union {
        LONG_PTR Balance : 2;           // AVL tree balance
        struct _MMVAD *Parent;
    };
    struct _MMVAD *LeftChild;
    struct _MMVAD *RightChild;

    ULONG_PTR StartingVpn;              // Starting virtual page number
    ULONG_PTR EndingVpn;                // Ending virtual page number

    union {
        ULONG LongFlags;
        struct {
            ULONG CommitCharge    : 19; // Pages committed
            ULONG MemCommit       : 1;  // Memory is committed
            ULONG Protection      : 5;  // Page protection
            ULONG NoChange        : 1;  // Cannot change protection
            ULONG PrivateMemory   : 1;  // Private memory
            // ... more flags
        };
    } u;

    PCONTROL_AREA ControlArea;          // Points to file mapping
    PVOID FirstPrototypePte;            // First prototype PTE
    PVOID LastContiguousPte;            // Last contiguous PTE
} MMVAD, *PMMVAD;
```

### VAD Tree trong EPROCESS

```c
typedef struct _EPROCESS {
    // ... other fields

    PMM_AVL_TABLE VadRoot;              // Root của VAD tree

    // ... more fields
} EPROCESS, *PEPROCESS;
```

### Enumerating VADs với WinDbg

**List tất cả VADs của một process:**

```
kd> !process 0 0 notepad.exe
PROCESS fffffa8012345678
    SessionId: 1  Cid: 1234    Peb: 7fffffde000  ParentCid: 5678
    DirBase: 1a5000  ObjectTable: fffff8a001234567  HandleCount: 234.
    Image: notepad.exe

kd> !vad fffffa8012345678
VAD     Level      Start          End          Commit
fffff6fb40123456  0   7ff7e0d0000  7ff7e0e0000      3 Private      READWRITE
fffff6fb40234567  1   7ff7e0e0000  7ff7e0f0000      5 Private      EXECUTE_READWRITE
fffff6fb40345678  2   7ff7e100000  7ff7e200000     16 Mapped       READONLY
...
```

**View detailed VAD info:**

```
kd> dt nt!_MMVAD fffff6fb40123456
   +0x000 Core             : _MMVAD_SHORT
   +0x040 u2               : _MMVAD_FLAGS2
   +0x044 Subsection       : 0xfffff6fb`40123400
   +0x04c FirstPrototypePte : 0xfffff6fb`40123500
   +0x054 LastContiguousPte : 0xfffff6fb`40123600
```

### Protection Flags trong VAD

VAD tracks page protection cho mỗi memory region:

| Value | Protection | Description |
|-------|-----------|-------------|
| 0x01 | PAGE_NOACCESS | No access |
| 0x02 | PAGE_READONLY | Read only |
| 0x04 | PAGE_READWRITE | Read/Write |
| 0x08 | PAGE_WRITECOPY | Copy-on-write |
| 0x10 | PAGE_EXECUTE | Execute only |
| 0x20 | PAGE_EXECUTE_READ | Execute/Read |
| 0x40 | PAGE_EXECUTE_READWRITE | Execute/Read/Write |
| 0x80 | PAGE_EXECUTE_WRITECOPY | Execute + COW |

---

## Physical Memory Management (PFN Database)

**PFN (Page Frame Number) Database** là một large array tracking tất cả physical memory pages trong system.

### PFN Structure

```c
typedef struct _MMPFN {
    union {
        PFN_NUMBER Flink;               // Forward link
        ULONG WsIndex;                  // Working set index
        PVOID VolatileVadAddress;       // VAD address
    } u1;

    PMMPTE PteAddress;                  // PTE pointing to this page

    union {
        PFN_NUMBER Blink;               // Backward link
        ULONG ShareCount;               // Share count
    } u2;

    union {
        struct {
            USHORT ReferenceCount;      // Reference count
            MMPFNENTRY e1;
        };
        struct {
            USHORT ReferenceCount;
            USHORT ShortFlags;
        };
        struct {
            USHORT ReferenceCount;
            UCHAR PageLocation   : 3;   // Active, Standby, Modified, etc.
            UCHAR WriteInProgress : 1;
            UCHAR Modified        : 1;
            UCHAR ReadInProgress  : 1;
            // ... more flags
        } u3;
    };

    ULONG_PTR OriginalPte;              // Original PTE contents

} MMPFN, *PMMPFN;
```

### Page States

Physical pages có thể ở nhiều states khác nhau:

```
┌─────────────────────────────────────────────┐
│           Page State Transitions             │
├─────────────────────────────────────────────┤
│                                             │
│  Free List ──────────┐                     │
│       ▲              │                     │
│       │              ▼                     │
│       │         Zeroed List                │
│       │              │                     │
│       │              ▼                     │
│       │         Active (In Use)            │
│       │              │                     │
│       │              ▼                     │
│       │      ┌───► Modified List           │
│       │      │       │                     │
│       └──────┤       ▼                     │
│              └── Standby List              │
│                      │                     │
│                      ▼                     │
│              Modified-No-Write List        │
│                                             │
└─────────────────────────────────────────────┘
```

**Page List Types:**

1. **Free List**: Pages available cho allocation, có thể contain old data
2. **Zeroed List**: Pages đã được zeroed, ready for allocation
3. **Active**: Pages đang được used bởi processes
4. **Modified**: Pages có dirty data chưa written back
5. **Standby**: Pages có valid data nhưng can be repurposed
6. **Modified-No-Write**: Modified pages không thể write to disk

### Viewing PFN Database với WinDbg

```
kd> !pfn 5e9
    PFN 000005E9 at address FFFFFA8000017248
    flink       000005EA  blink / share count 000005E8  pteaddress FFFFF6FB40001234
    reference count 0001    used entry count  0000       color 0
    restore pte 00000000  containing page 001234  Active     M
    Modified
```

---

## Memory Pools (Paged vs Non-Paged)

Kernel allocates memory từ **pools** - pre-allocated regions cho dynamic allocations.

### Pool Types

**Paged Pool:**
- Có thể paged out to disk
- Used cho non-critical allocations
- Larger size available
- Performance hit khi page faults occur

**Non-Paged Pool:**
- Always resident trong RAM
- Used cho critical structures (locks, DPCs, interrupt handling)
- Limited size (exhaustion = BSOD)
- Better performance (no page faults)

### Pool Header Structure

```c
typedef struct _POOL_HEADER {
    union {
        struct {
            USHORT PreviousSize : 9;    // Size of previous block
            USHORT PoolIndex    : 7;    // Pool index
            USHORT BlockSize    : 9;    // Size of this block
            USHORT PoolType     : 7;    // Pool type
        };
        ULONG Ulong1;
    };

    ULONG PoolTag;                       // 4-byte pool tag (e.g., 'File', 'Proc')

    union {
        PEPROCESS ProcessBilled;         // Process charged for allocation
        struct {
            USHORT AllocatorBackTraceIndex;
            USHORT PoolTagHash;
        };
    };
} POOL_HEADER, *PPOOL_HEADER;
```

### Pool Tags

Pool tags là 4-character identifiers used để track allocations:

```
Common Pool Tags:
- 'File' - File objects
- 'Proc' - Process objects
- 'Thrd' - Thread objects
- 'IoPt' - I/O Pool Tag
- 'Even' - Event objects
- 'Sema' - Semaphore objects
```

### Viewing Pools với WinDbg

**List all pool allocations:**

```
kd> !poolused
Sorting by  Tag

  Pool  Used      NonPaged            Paged
  Tag   Size      Allocs   Size      Allocs
-----------------------------------------------
 .ETW      0          0   1a2c480     2468  Event Tracing
  AfdE      0          0   b84aa0       467  AFD endpoint structures
  CM25 3a1a8c0     13437       0          0  Configuration Manager
  Cont  14e1e0         3   4c5c60       271  Device object containers
  File 1023480      3956  11d9200     12847  File objects
```

**View pool with specific tag:**

```
kd> !poolfind File
Scanning large pool allocation table for Tag: File (fffff80001234000 : fffff80002345000)

fffff80012345678 size:  240 previous size:    0  (Allocated) *File
fffff80012345900 size:  240 previous size:  240  (Allocated)  File
...
```

**Examine pool header:**

```
kd> dt nt!_POOL_HEADER fffff80012345678
   +0x000 PreviousSize     : 0y000000000 (0)
   +0x000 PoolIndex        : 0y0000000 (0)
   +0x002 BlockSize        : 0y000100100 (0x24)
   +0x002 PoolType         : 0y0000010 (0x2)
   +0x004 PoolTag          : 0x656c6946 'File'
```

---

## Practical Exploitation Techniques

### 1. Pool Spraying

Pool spraying là technique để control heap layout cho exploitation:

```c
// Spray non-paged pool with controlled objects
for (int i = 0; i < 10000; i++) {
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    // Events allocated từ non-paged pool
    // Store handles để prevent deallocation
    eventHandles[i] = hEvent;
}

// Trigger vulnerability (use-after-free, overflow, etc.)
TriggerVulnerability();

// Freed object giờ surrounded bởi controlled Event objects
// Exploit có thể predict memory layout
```

**Why This Works:**
- Pool allocator uses best-fit algorithm
- Objects cùng size allocated gần nhau
- Spraying tạo predictable layout
- Useful cho heap feng shui

### 2. VAD Manipulation

Attackers có thể manipulate VAD structures để:

**Hide Memory Regions:**
```c
// Unlink VAD entry từ tree
PMMVAD pVad = FindVadByAddress(targetAddress);
RemoveVadFromTree(pVad);
// Region giờ invisible cho tools enumerate memory
```

**Change Memory Protection:**
```c
// Modify VAD protection flags
pVad->u.VadFlags.Protection = PAGE_EXECUTE_READWRITE;
// Memory region giờ executable without calling VirtualProtect
```

### 3. PTE Manipulation

Direct PTE manipulation là powerful technique:

```c
// Find PTE cho một virtual address
PMMPTE pte = MiGetPteAddress(virtualAddress);

// Make read-only page writable
pte->u.Hard.Write = 1;

// Make non-executable page executable (disable NX)
pte->u.Hard.NoExecute = 0;

// Flush TLB để apply changes
__invlpg(virtualAddress);
```

**Applications:**
- Bypass W^X policies
- Patch kernel code pages (if HVCI disabled)
- Modify driver .text sections
- Hook kernel functions

### 4. Physical Memory Access

Với arbitrary read/write trong kernel, có thể access physical memory directly:

```c
// Map physical memory vào kernel address space
PHYSICAL_ADDRESS physAddr;
physAddr.QuadPart = 0x1000;  // Physical address

PVOID mappedAddress = MmMapIoSpace(
    physAddr,
    PAGE_SIZE,
    MmNonCached
);

// Read/write physical memory
*(PULONG)mappedAddress = 0x90909090;  // NOP sled

MmUnmapIoSpace(mappedAddress, PAGE_SIZE);
```

---

## Memory Mitigations

### ASLR (Address Space Layout Randomization)

**User Mode ASLR:**
- Randomizes base addresses của executables, DLLs, heaps, stacks
- Makes exploitation harder (need info leaks)
- Can be bypassed với memory leaks

**Kernel ASLR (KASLR):**
- Randomizes kernel base address
- Drivers cũng randomized
- Info leaks critical cho kernel exploitation

### DEP (Data Execution Prevention)

Based trên NX bit trong PTEs:
- Stack non-executable by default
- Heap non-executable
- Data sections non-executable
- Bypassed bằng ROP/JOP

### SMEP (Supervisor Mode Execution Prevention)

Prevents kernel từ executing user-mode code:
- Checked via PTE Owner bit
- Makes kernel exploits harder
- Bypass requires ROP trong kernel space hoặc disable SMEP

### Control Flow Guard (CFG)

Protects indirect calls:
- Validates call targets
- Prevents control flow hijacking
- Kernel variant: kCFG

---

## Lab Exercises với WinDbg

### Exercise 1: Walk Page Tables Manually

```
kd> r cr3
cr3=00000000001a5000

kd> !pte 0xFFFFF80012345678
                    VA fffff80012345678
PXE at FFFFF6FB7DBEDF80    PPE at FFFFF6FB7DBF0000    PDE at FFFFF6FB7E000048    PTE at FFFFF6FC00091A28
contains 000000001A5063    contains 000000002B6063    contains 000000003C7063    contains 0000000005E9867
pfn 1a5       ---DA--KWEV    pfn 2b6       ---DA--KWEV    pfn 3c7       ---DA--KWEV    pfn 5e9       -G-DA--KW-V

kd> !pfn 5e9
    PFN 000005E9 at address FFFFFA8000017248
    Active     M
```

### Exercise 2: Find Executable Memory trong Process

```
kd> !process 0 0 calc.exe
PROCESS fffffa8012345678

kd> .process /p fffffa8012345678

kd> !vad
VAD            Start       End         Protection
fffff6fb40123456  7ff000000  7ff100000  EXECUTE_READ
fffff6fb40234567  7ff200000  7ff300000  EXECUTE_READWRITE
```

### Exercise 3: Pool Feng Shui Analysis

```
kd> !poolused 2

kd> !poolfind Leak

kd> dt nt!_POOL_HEADER <address>
```

---

## Wrapup

Windows memory management là một complex subsystem với nhiều layers: virtual memory abstraction, page table translations, VAD tracking, và physical memory management thông qua PFN database.

Understanding memory internals này critical cho:

- **Kernel exploitation**: Manipulating PTEs, VADs, pool structures
- **Malware development**: Hiding memory, direct physical access
- **Rootkit development**: Memory stealth techniques
- **Vulnerability research**: Identifying memory corruption bugs

Knowledge về page tables, VAD trees, và pool allocations là foundation cho advanced Windows exploitation techniques.

---

## References

**Books:**
- **Windows Internals, Part 1** (Chapter 5: Memory Management) - Russinovich, Solomon, Ionescu
- **Windows Kernel Programming** (Chapter 8: Memory) - Pavel Yosifovich
- **What Makes It Page?** - Enrico Martignetti

**Papers:**
- "Windows Kernel Pool Spraying" - Tarjei Mandt
- "Exploiting the Windows Kernel" - mxatone
- "Kernel Pool Exploitation on Windows 7" - Mandt

**Tools:**
- [WinDbg Preview](https://apps.microsoft.com/detail/9PGJGD53TN86)
- [Volatility](https://www.volatilityfoundation.org/) - Memory forensics
- [MemProcFS](https://github.com/ufrisk/MemProcFS) - Memory analysis

---

<h2><strong style="color: red;">Master memory, control the system.</strong></h2>
