---
title: "The Dark Arts of PE Loading in Windows"
published: 2022-01-22   
description: ""
image: ""
tags:
  - "WindowsInternal"
category: "Cybersecurity"
draft: false 
lang: "en"
---
# **Giới thiệu**
Thông thường, khi chúng ta chạy một chương trình .exe hoặc nạp một thư viện .dll, hệ điều hành Windows sẽ thay chúng ta xử lý mọi thứ: từ việc đọc file trên đĩa, cấp phát bộ nhớ, nạp mã máy, đến việc khởi chạy chương trình. Tất cả được thực hiện thông qua các hàm như CreateProcess, LoadLibrary hoặc ShellExecute.

Nhưng điều gì sẽ xảy ra nếu chúng ta không thể – hoặc không muốn – sử dụng những hàm này?
Trong một số tình huống đặc biệt như:
- Chúng ta muốn chạy chương trình từ bộ nhớ mà không cần ghi ra đĩa.
- Cần ẩn hành vi thực thi khỏi phần mềm bảo mật.
- Hoặc đơn giản là muốn hiểu rõ cách Windows thực sự hoạt động bên trong.
... thì RunPE sẽ là một lựa chọn mạnh mẽ.
# **PEB là gì?**
Khi nhắc tới việc không gọi WinAPI trực tiếp chúng ta không thể nào không nhắc tới PEB. Vậy PEB là gì?
![alt text](<browse-peb1.png>)
PEB (Process Environment Block) là một cấu trúc dữ liệu nội bộ của Windows, lưu trữ thông tin về process đang chạy. Nó tồn tại trong không gian bộ nhớ của mỗi process và được hệ điều hành sử dụng để quản lý process đó. Tuy không được document công khai đầy đủ bởi Microsoft nhưng chúng ta có thể tra trong `winternl.h` hoặc Reverse từ `ntdll.dll`.
# **Manual PE Loading**
Thay vì nhờ hệ điều hành nạp và thực thi chương trình, chúng ta sẽ tự mình đảm nhiệm vai trò đó. Cụ thể, chúng ta sẽ:
## **File Loading** 
CreateFileA -> VirtualAlloc
- Mở file PE
- Lấy file size
- Allocate memory với PAGE_READWRITE
- Đọc toàn bộ file vào memory:  sẽ có 2 phương pháp 1 là chúng ta có thể đọc file vào memory, 2 là chúng ta có thể dùng CreateFileMappingA và MapViewOfFile.
🔸 Memory Mapping: Dùng CreateFileMapping + MapViewOfFile (Windows API) để ánh xạ nội dung file vào không gian địa chỉ ảo của process.
```cpp
HANDLE hFile = CreateFile(...);
HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID pData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
```
🔸 ReadFile: Dùng các hàm như ReadFile, fread, ifstream.read() để đọc nội dung file thành từng khối vào buffer bộ nhớ.
```cpp
HANDLE hFile = CreateFile(...);
ReadFile(hFile, buffer, size, &bytesRead, NULL);
```
Áp dụng kĩ thuật file maping ta có:
```cpp
class FileMap {
public:
    explicit FileMap(const std::string& path) {
        file_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[FileMap] Cannot open " << path << " (" << GetLastError() << ")\n";
            return;
        }
        size_ = GetFileSize(file_, nullptr);
        mapping_ = CreateFileMappingA(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_) {
            std::cerr << "[FileMap] CreateFileMapping failed (" << GetLastError() << ")\n";
            return;
        }
        view_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) {
            std::cerr << "[FileMap] MapViewOfFile failed (" << GetLastError() << ")\n";
        }
    }
    ~FileMap() {
        if (view_)    UnmapViewOfFile(view_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    }
    [[nodiscard]] bool        valid() const { return view_ != nullptr; }
    [[nodiscard]] const void* data()  const { return view_; }
    [[nodiscard]] DWORD       size()  const { return size_; }

private:
    HANDLE file_{ INVALID_HANDLE_VALUE };
    HANDLE mapping_{ nullptr };
    LPVOID view_{ nullptr };
    DWORD  size_{ 0 };
};
```

- Return pointer và file size
## **Fix IAT**:
```cpp
bool resolveImports() {
    auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.Size) return true;
    auto imp = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(util::rvaToPtr(image_, dir.VirtualAddress));
    while (imp->Name) {
        const char* dllName = reinterpret_cast<char*>(util::rvaToPtr(image_, imp->Name));
        HMODULE dll = LoadLibraryA(dllName);
        if (!dll) { std::cerr << "[!] Cannot load " << dllName << "\n"; return false; }
        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(util::rvaToPtr(image_, imp->FirstThunk));
        auto orig = reinterpret_cast<PIMAGE_THUNK_DATA>(util::rvaToPtr(image_, imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        for (; orig->u1.AddressOfData; ++orig, ++thunk) {
            FARPROC fp;
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                fp = GetProcAddress(dll, MAKEINTRESOURCEA(IMAGE_ORDINAL(orig->u1.Ordinal)));
            }
            else {
                auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(util::rvaToPtr(image_, orig->u1.AddressOfData));
                fp = (std::strcmp("ExitProcess", ibn->Name) == 0) ? reinterpret_cast<FARPROC>(&ExitProcessHook)
                    : GetProcAddress(dll, ibn->Name);
            }
            thunk->u1.Function = reinterpret_cast<ULONGLONG>(fp);
        }
        ++imp;
    }
    return true;
}
```
- Tìm Import Table: Từ DataDirectory[1]
- Duyệt từng DLL: kernel32.dll, user32.dll, etc.
- Load DLL: LoadLibraryA()
- Resolve Functions: GetProcAddress()
- Update FirstThunk: Ghi địa chỉ function vào IAT
- Special Handling: Intercept ExitProcess
## **Fix Reloc**: 
Thực hiện relocation khi PE không load tại preferred base address
- Delta: Difference giữa actual và preferred base
- Fix addresses: Cộng delta vào các absolute addresses
```cpp
bool relocate() {
    ULONGLONG delta = reinterpret_cast<ULONGLONG>(image_) - nt_->OptionalHeader.ImageBase;
    if (!delta) return true;
    auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.Size) { std::cerr << "[reloc] table missing\n"; return false; }
    auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(util::rvaToPtr(image_, dir.VirtualAddress));
    while (reloc->SizeOfBlock) {
        auto entries = reinterpret_cast<PWORD>(reloc + 1);
        int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (int i = 0; i < count; ++i) {
            WORD type = entries[i] >> 12; WORD off = entries[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
                auto patch = reinterpret_cast<PULONGLONG>(util::rvaToPtr(image_, reloc->VirtualAddress + off));
                *patch += delta;
            }
        }
        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
    }
    return true;
}
```
## **Parameter Hijacking**
Thông thường, khi một chương trình C/cpp được khởi chạy, nó nhận các đối số dòng lệnh theo dạng:
```cpp
int main(int argc, char* argv[])
```
Tuy nhiên, trong thực tế, `main()` không phải là entry point của process. Trước khi gọi đến `main()`, hệ thống runtime của C (CRT) sẽ thực hiện một số bước khởi tạo quan trọng. Cụ thể, chương trình sẽ gọi các hàm như:
* `GetCommandLineA()` / `GetCommandLineW()` để lấy chuỗi lệnh ban đầu,
* `GetEnvironmentStrings()` để lấy biến môi trường,
Sau đó, chuỗi dòng lệnh sẽ được phân tích cú pháp thành mảng `argv`, giá trị `argc`, và biến môi trường `envp`. Các thông tin này sẽ được gán vào những biến toàn cục như:
```cpp
__argc, __argv, _environ
```
Và sau cùng, CRT mới gọi:
```cpp
main(__argc, __argv, _environ);
```
Do đó, nếu chúng ta muốn (`parameter hijacking`) **chỉ thực hiện sửa chuỗi dòng lệnh trong PEB thôi là chưa đủ**. Chúng ta **phải can thiệp đồng thời vào 3 khu vực sau** để đảm bảo chương trình mục tiêu nhận đúng đối số giả mạo:
- **Process Environment Block**
    * Chứa chuỗi `CommandLine` và `ImagePathName`.
    * Được dùng bởi các API hệ thống như `GetCommandLineW()`.
- **Thư viện `MSVCRT.dll` (hoặc `ucrtbase.dll`)**
    * Lưu trữ các biến toàn cục: `__argc`, `__argv`, `__wargv`, `_environ`, v.v.
    * Được sử dụng trực tiếp trong `main()` hoặc các hàm C tiêu chuẩn.
- **Thư viện `KERNELBASE.dll`**
    * Một số bản sao hoặc ánh xạ của các biến kể trên cũng tồn tại trong `KERNELBASE.dll` (tùy phiên bản Windows).
    * Một số runtime hiện đại có thể truy cập gián tiếp thông qua thư viện này.

## **Execution Strategy**
Execution Methods:
- EXE: Tạo thread mới, gọi entry point như main()
- DLL: Gọi DllMain với DLL_PROCESS_ATTACH

# Final
![alt text](<out.png>)

## Full POC
```cpp

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <cstring>

#pragma comment(lib, "kernel32.lib")

// --------------------------------------------------
// Utility
// --------------------------------------------------
namespace util {
    inline LPVOID rvaToPtr(LPVOID base, DWORD rva) {
        return static_cast<BYTE*>(base) + rva;
    }
}

// --------------------------------------------------
// RAII file‑mapping wrapper
// --------------------------------------------------
class FileMap {
public:
    explicit FileMap(const std::string& path) {
        file_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[FileMap] Cannot open " << path << " (" << GetLastError() << ")\n";
            return;
        }
        size_ = GetFileSize(file_, nullptr);
        mapping_ = CreateFileMappingA(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_) {
            std::cerr << "[FileMap] CreateFileMapping failed (" << GetLastError() << ")\n";
            return;
        }
        view_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) {
            std::cerr << "[FileMap] MapViewOfFile failed (" << GetLastError() << ")\n";
        }
    }
    ~FileMap() {
        if (view_)    UnmapViewOfFile(view_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    }
    [[nodiscard]] bool   valid() const { return view_ != nullptr; }
    [[nodiscard]] const void* data()  const { return view_; }
    [[nodiscard]] DWORD  size()  const { return size_; }

private:
    HANDLE file_{ INVALID_HANDLE_VALUE };
    HANDLE mapping_{ nullptr };
    LPVOID view_{ nullptr };
    DWORD  size_{ 0 };
};

// --------------------------------------------------
// Command‑line helper (skips first <skip> parameters)
// --------------------------------------------------
class CommandLine {
public:
    CommandLine(int argc, char* argv[], int skip = 0) {
        for (int i = skip; i < argc; ++i) args_.emplace_back(argv[i]);
        buildRaw();
        buildArgv();
    }
    [[nodiscard]] int      argc() const { return static_cast<int>(args_.size()); }
    [[nodiscard]] char**   argv() const { return argv_.get(); }
    [[nodiscard]] LPCSTR   raw()  const { return raw_.c_str(); }

private:
    void buildRaw() {
        for (size_t i = 0; i < args_.size(); ++i) {
            if (i) raw_ += ' ';
            const auto& s = args_[i];
            if (s.find_first_of(" \t") != std::string::npos) raw_ += '"' + s + '"';
            else raw_ += s;
        }
    }
    void buildArgv() {
        argv_ = std::make_unique<char*[]>(args_.size());
        for (size_t i = 0; i < args_.size(); ++i) argv_[i] = args_[i].data();
    }
    std::vector<std::string> args_;
    std::string              raw_;
    std::unique_ptr<char*[]> argv_;
};

// Forward decl so static hook can access loader instance
class PELoader;
static PELoader* g_loader = nullptr;

// --------------------------------------------------
// PE loader (single‑file, minimal OOP)
// --------------------------------------------------
class PELoader {
public:
    explicit PELoader(CommandLine& cmd) : cmd_(cmd) { g_loader = this; }

    // Intercept ExitProcess so the host process keeps control
    static void WINAPI ExitProcessHook(UINT code) {
        if (g_loader) {
            g_loader->exitCalled_ = true;
            g_loader->exitCode_  = code;
            std::cout << "[+] ExitProcess intercepted — code=" << code << "\n";
        }
    }

    bool load(const std::string& path) {
        map_ = std::make_unique<FileMap>(path);
        if (!map_->valid()) return false;
        if (!isValidPE(map_->data())) { std::cerr << "[!] Invalid PE file\n"; return false; }
        nt_    = getNtHeaders(map_->data());
        image_ = allocateImage(nt_);
        if (!image_) return false;
        copyImage();
        nt_ = getNtHeaders(image_);
        return resolveImports() && applyRelocations();
    }

    int run() { return image_ ? callEntry() : -1; }

private:
    // ---------- helpers ----------
    static bool isValidPE(const void* data) {
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(static_cast<const BYTE*>(data) + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE;
    }
    static PIMAGE_NT_HEADERS getNtHeaders(const void* base) {
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        return reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<BYTE*>(const_cast<void*>(base)) + dos->e_lfanew);
    }
    LPVOID allocateImage(PIMAGE_NT_HEADERS nt) {
        SIZE_T sz = nt->OptionalHeader.SizeOfImage;
        auto preferred = reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase);
        auto mem = VirtualAlloc(preferred, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        return mem ? mem : VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    void copyImage() {
        std::memcpy(image_, map_->data(), nt_->OptionalHeader.SizeOfHeaders);
        auto section = IMAGE_FIRST_SECTION(nt_);
        for (int i = 0; i < nt_->FileHeader.NumberOfSections; ++i, ++section) {
            if (!section->SizeOfRawData) continue;
            std::memcpy(util::rvaToPtr(image_, section->VirtualAddress),
                        static_cast<const BYTE*>(map_->data()) + section->PointerToRawData,
                        section->SizeOfRawData);
        }
    }

    bool resolveImports() {
        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.Size) return true;
        auto imp = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(util::rvaToPtr(image_, dir.VirtualAddress));
        while (imp->Name) {
            const char* dllName = reinterpret_cast<char*>(util::rvaToPtr(image_, imp->Name));
            HMODULE dll = LoadLibraryA(dllName);
            if (!dll) { std::cerr << "[!] Cannot load " << dllName << "\n"; return false; }
            auto thunkName = reinterpret_cast<PIMAGE_THUNK_DATA>(util::rvaToPtr(image_, imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto thunkIAT  = reinterpret_cast<PIMAGE_THUNK_DATA>(util::rvaToPtr(image_, imp->FirstThunk));
            while (thunkName->u1.AddressOfData) {
                FARPROC func = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal)) {
                    func = GetProcAddress(dll, MAKEINTRESOURCEA(IMAGE_ORDINAL(thunkName->u1.Ordinal)));
                } else {
                    auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(util::rvaToPtr(image_, thunkName->u1.AddressOfData));
                    func = (std::strcmp("ExitProcess", ibn->Name) == 0) ? reinterpret_cast<FARPROC>(&ExitProcessHook)
                                                                          : GetProcAddress(dll, ibn->Name);
                }
                thunkIAT->u1.Function = reinterpret_cast<ULONGLONG>(func);
                ++thunkName; ++thunkIAT;
            }
            ++imp;
        }
        return true;
    }

    bool applyRelocations() {
        ULONGLONG delta = reinterpret_cast<ULONGLONG>(image_) - nt_->OptionalHeader.ImageBase;
        if (!delta) return true;
        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!dir.Size) { std::cerr << "[reloc] table missing\n"; return false; }
        auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(util::rvaToPtr(image_, dir.VirtualAddress));
        while (reloc->SizeOfBlock) {
            auto count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto entry = reinterpret_cast<PWORD>(reloc + 1);
            for (DWORD i = 0; i < count; ++i, ++entry) {
                WORD type = *entry >> 12; WORD off = *entry & 0xFFF;
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    auto patch = reinterpret_cast<PULONGLONG>(util::rvaToPtr(image_, reloc->VirtualAddress + off));
                    *patch += delta;
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
        }
        return true;
    }

    int callEntry() {
        auto entry = util::rvaToPtr(image_, nt_->OptionalHeader.AddressOfEntryPoint);
        if (nt_->FileHeader.Characteristics & IMAGE_FILE_DLL) {
            auto dllMain = reinterpret_cast<BOOL (WINAPI*)(HINSTANCE,DWORD,LPVOID)>(entry);
            dllMain(reinterpret_cast<HINSTANCE>(image_), DLL_PROCESS_ATTACH, nullptr);
            return 0;
        }
        if (nt_->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
            auto winMain = reinterpret_cast<int (WINAPI*)(HINSTANCE,HINSTANCE,LPSTR,int)>(entry);
            return winMain(reinterpret_cast<HINSTANCE>(image_), nullptr, const_cast<char*>(cmd_.raw()), SW_SHOWDEFAULT);
        }
        auto mainFn = reinterpret_cast<int (*)(int,char**)>(entry);
        return mainFn(cmd_.argc(), cmd_.argv());
    }

    // ---------- members ----------
    CommandLine&                 cmd_;
    std::unique_ptr<FileMap>     map_;
    PIMAGE_NT_HEADERS            nt_ { nullptr };
    LPVOID                       image_ { nullptr };
    bool                         exitCalled_ { false };
    DWORD                        exitCode_   { 0 };
};

// --------------------------------------------------
// Entry point
// --------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <pe_file> [arguments...]\n";
        return 1;
    }
    CommandLine cmd(argc, argv, 2); // skip exe + target path
    PELoader loader(cmd);
    if (!loader.load(argv[1])) return 1;
    return loader.run();
}

<<<<<<< HEAD
```
With delay import
```cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <cstring>

#pragma comment(lib, "kernel32.lib")

// Delay import structures (in case SDK doesn't have them)
#ifndef IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#endif

#if (defined(_WIN32_WINNT) && _WIN32_WINNT <= 0x0601) && !defined(__MINGW32__)
#include "pshpack4.h"
typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RvaBased : 1;             // Delay load version 2
            DWORD ReservedAttributes : 31;
        } DUMMYSTRUCTNAME;
    } Attributes;

    DWORD DllNameRVA;                       // RVA to the name of the target library
    DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location
    DWORD ImportAddressTableRVA;            // RVA to the start of the IAT
    DWORD ImportNameTableRVA;               // RVA to the start of the name table
    DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
    DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
    DWORD TimeDateStamp;                    // 0 if not bound
} IMAGE_DELAYLOAD_DESCRIPTOR, * PIMAGE_DELAYLOAD_DESCRIPTOR;
#include "poppack.h"
#endif

// --------------------------------------------------
// Utility
// --------------------------------------------------
namespace util {
    inline LPVOID rvaToPtr(LPVOID base, DWORD rva) {
        return static_cast<BYTE*>(base) + rva;
    }

    inline bool validatePtr(LPVOID base, SIZE_T baseSize, LPVOID ptr, SIZE_T ptrSize) {
        auto start = reinterpret_cast<ULONG_PTR>(base);
        auto end = start + baseSize;
        auto check = reinterpret_cast<ULONG_PTR>(ptr);
        return (check >= start) && (check + ptrSize <= end);
    }
}

// --------------------------------------------------
// RAII file‑mapping wrapper
// --------------------------------------------------
class FileMap {
public:
    explicit FileMap(const std::string& path) {
        file_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[FileMap] Cannot open " << path << " (" << GetLastError() << ")\n";
            return;
        }
        size_ = GetFileSize(file_, nullptr);
        mapping_ = CreateFileMappingA(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_) {
            std::cerr << "[FileMap] CreateFileMapping failed (" << GetLastError() << ")\n";
            return;
        }
        view_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) {
            std::cerr << "[FileMap] MapViewOfFile failed (" << GetLastError() << ")\n";
        }
    }
    ~FileMap() {
        if (view_)    UnmapViewOfFile(view_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    }
    [[nodiscard]] bool   valid() const { return view_ != nullptr; }
    [[nodiscard]] const void* data()  const { return view_; }
    [[nodiscard]] DWORD  size()  const { return size_; }

private:
    HANDLE file_{ INVALID_HANDLE_VALUE };
    HANDLE mapping_{ nullptr };
    LPVOID view_{ nullptr };
    DWORD  size_{ 0 };
};

// --------------------------------------------------
// Command‑line helper (skips first <skip> parameters)
// --------------------------------------------------
class CommandLine {
public:
    CommandLine(int argc, char* argv[], int skip = 0) {
        for (int i = skip; i < argc; ++i) args_.emplace_back(argv[i]);
        buildRaw();
        buildArgv();
    }
    [[nodiscard]] int      argc() const { return static_cast<int>(args_.size()); }
    [[nodiscard]] char** argv() const { return argv_.get(); }
    [[nodiscard]] LPCSTR   raw()  const { return raw_.c_str(); }

private:
    void buildRaw() {
        for (size_t i = 0; i < args_.size(); ++i) {
            if (i) raw_ += ' ';
            const auto& s = args_[i];
            if (s.find_first_of(" \t") != std::string::npos) raw_ += '"' + s + '"';
            else raw_ += s;
        }
    }
    void buildArgv() {
        argv_ = std::make_unique<char* []>(args_.size());
        for (size_t i = 0; i < args_.size(); ++i) argv_[i] = args_[i].data();
    }
    std::vector<std::string> args_;
    std::string              raw_;
    std::unique_ptr<char* []> argv_;
};

// Forward decl so static hook can access loader instance
class PELoader;
static PELoader* g_loader = nullptr;

// --------------------------------------------------
// PE loader (single‑file, minimal OOP) with delay import support
// --------------------------------------------------
class PELoader {
public:
    explicit PELoader(CommandLine& cmd) : cmd_(cmd) { g_loader = this; }

    // Intercept ExitProcess so the host process keeps control
    static void WINAPI ExitProcessHook(UINT code) {
        if (g_loader) {
            g_loader->exitCalled_ = true;
            g_loader->exitCode_ = code;
            std::cout << "[+] ExitProcess intercepted — code=" << code << "\n";
        }
    }

    bool load(const std::string& path) {
        map_ = std::make_unique<FileMap>(path);
        if (!map_->valid()) return false;
        if (!isValidPE(map_->data())) {
            std::cerr << "[!] Invalid PE file\n";
            return false;
        }

        nt_ = getNtHeaders(map_->data());
        imageSize_ = nt_->OptionalHeader.SizeOfImage;
        image_ = allocateImage(nt_);
        if (!image_) return false;

        copyImage();
        nt_ = getNtHeaders(image_);

        return resolveImports() && resolveDelayImports() && applyRelocations();
    }

    int run() { return image_ ? callEntry() : -1; }

private:
    // ---------- helpers ----------
    static bool isValidPE(const void* data) {
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(static_cast<const BYTE*>(data) + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE;
    }

    static PIMAGE_NT_HEADERS getNtHeaders(const void* base) {
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        return reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<BYTE*>(const_cast<void*>(base)) + dos->e_lfanew);
    }

    LPVOID allocateImage(PIMAGE_NT_HEADERS nt) {
        SIZE_T sz = nt->OptionalHeader.SizeOfImage;
        auto preferred = reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase);
        auto mem = VirtualAlloc(preferred, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        return mem ? mem : VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    void copyImage() {
        std::memcpy(image_, map_->data(), nt_->OptionalHeader.SizeOfHeaders);
        auto section = IMAGE_FIRST_SECTION(nt_);
        for (int i = 0; i < nt_->FileHeader.NumberOfSections; ++i, ++section) {
            if (!section->SizeOfRawData) continue;
            std::memcpy(util::rvaToPtr(image_, section->VirtualAddress),
                static_cast<const BYTE*>(map_->data()) + section->PointerToRawData,
                section->SizeOfRawData);
        }
    }

    bool resolveImports() {
        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.Size) return true;

        auto imp = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(util::rvaToPtr(image_, dir.VirtualAddress));
        while (imp->Name) {
            const char* dllName = reinterpret_cast<char*>(util::rvaToPtr(image_, imp->Name));
            HMODULE dll = LoadLibraryA(dllName);
            if (!dll) {
                std::cerr << "[!] Cannot load " << dllName << "\n";
                return false;
            }

            auto thunkName = reinterpret_cast<PIMAGE_THUNK_DATA>(
                util::rvaToPtr(image_, imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto thunkIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(util::rvaToPtr(image_, imp->FirstThunk));

            while (thunkName->u1.AddressOfData) {
                FARPROC func = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal)) {
                    func = GetProcAddress(dll, MAKEINTRESOURCEA(IMAGE_ORDINAL(thunkName->u1.Ordinal)));
                }
                else {
                    auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        util::rvaToPtr(image_, thunkName->u1.AddressOfData));
                    func = (std::strcmp("ExitProcess", ibn->Name) == 0)
                        ? reinterpret_cast<FARPROC>(&ExitProcessHook)
                        : GetProcAddress(dll, ibn->Name);
                }
                thunkIAT->u1.Function = reinterpret_cast<ULONGLONG>(func);
                ++thunkName; ++thunkIAT;
            }
            ++imp;
        }
        return true;
    }

    bool resolveDelayImports() {
        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (!dir.Size) {
            std::cout << "[+] No delay imports to resolve\n";
            return true; // No delay imports
        }

        std::cout << "[+] Processing delay imports...\n";
        auto desc = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(util::rvaToPtr(image_, dir.VirtualAddress));

        while (desc->DllNameRVA) {
            if (!util::validatePtr(image_, imageSize_, desc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) {
                std::cerr << "[!] Invalid delay import descriptor\n";
                return false;
            }

            // Get DLL name
            ULONGLONG imageBase = nt_->OptionalHeader.ImageBase;
            ULONGLONG dllNameRva = desc->DllNameRVA;
            if (dllNameRva > imageBase) {
                dllNameRva -= imageBase; // Convert VA to RVA if needed
            }

            const char* dllName = reinterpret_cast<const char*>(util::rvaToPtr(image_, dllNameRva));
            if (!util::validatePtr(image_, imageSize_, const_cast<char*>(dllName), 1)) {
                std::cerr << "[!] Invalid DLL name in delay import\n";
                return false;
            }

            std::cout << "[+] Processing delay import DLL: " << dllName << "\n";

            // Process delay import functions
            bool success = false;
#ifdef _WIN64
            success = processDelayImport<ULONGLONG, IMAGE_THUNK_DATA64>(
                desc, dllName, imageBase, IMAGE_ORDINAL_FLAG64);
#else
            success = processDelayImport<DWORD, IMAGE_THUNK_DATA32>(
                desc, dllName, imageBase, IMAGE_ORDINAL_FLAG32);
#endif
            if (!success) {
                std::cerr << "[!] Failed to process delay imports for " << dllName << "\n";
                return false;
            }

            ++desc;
        }

        std::cout << "[+] Delay imports resolved successfully\n";
        return true;
    }

    template<typename T_FIELD, typename T_IMAGE_THUNK_DATA>
    bool processDelayImport(PIMAGE_DELAYLOAD_DESCRIPTOR desc, const char* dllName,
        ULONGLONG imageBase, T_FIELD ordinalFlag) {
        // Load the DLL
        HMODULE dll = LoadLibraryA(dllName);
        if (!dll) {
            std::cerr << "[!] Cannot load delay import DLL: " << dllName << "\n";
            return false;
        }

        // Get RVAs
        ULONGLONG iatRva = desc->ImportAddressTableRVA;
        if (iatRva > imageBase) iatRva -= imageBase;

        ULONGLONG thunkRva = desc->ImportNameTableRVA;
        if (thunkRva > imageBase) thunkRva -= imageBase;

        // Get pointers to tables
        auto iatPtr = reinterpret_cast<T_FIELD*>(util::rvaToPtr(image_, iatRva));
        auto thunkPtr = reinterpret_cast<T_IMAGE_THUNK_DATA*>(util::rvaToPtr(image_, thunkRva));

        // Process each function
        while (*iatPtr && thunkPtr->u1.AddressOfData) {
            if (!util::validatePtr(image_, imageSize_, iatPtr, sizeof(T_FIELD)) ||
                !util::validatePtr(image_, imageSize_, thunkPtr, sizeof(T_IMAGE_THUNK_DATA))) {
                std::cerr << "[!] Invalid delay import thunk\n";
                return false;
            }

            FARPROC func = nullptr;

            // Check if import by ordinal
            if (thunkPtr->u1.Ordinal & ordinalFlag) {
                T_FIELD ordinal = thunkPtr->u1.Ordinal & (~ordinalFlag);
                func = GetProcAddress(dll, MAKEINTRESOURCEA(ordinal));
            }
            else {
                // Import by name
                ULONGLONG nameRva = thunkPtr->u1.AddressOfData;
                if (nameRva > imageBase) nameRva -= imageBase;

                auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(util::rvaToPtr(image_, nameRva));
                if (!util::validatePtr(image_, imageSize_, ibn, sizeof(IMAGE_IMPORT_BY_NAME))) {
                    std::cerr << "[!] Invalid import by name structure\n";
                    return false;
                }

                const char* funcName = reinterpret_cast<const char*>(ibn->Name);
                if (std::strcmp("ExitProcess", funcName) == 0) {
                    func = reinterpret_cast<FARPROC>(&ExitProcessHook);
                }
                else {
                    func = GetProcAddress(dll, funcName);
                }
            }

            if (func) {
                // Rather than using proxy functions, directly patch the IAT
                *iatPtr = reinterpret_cast<T_FIELD>(func);
            }
            else {
                std::cerr << "[!] Failed to resolve delay import function\n";
                return false;
            }

            ++iatPtr;
            ++thunkPtr;
        }

        return true;
    }

    bool applyRelocations() {
        ULONGLONG delta = reinterpret_cast<ULONGLONG>(image_) - nt_->OptionalHeader.ImageBase;
        if (!delta) return true;

        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!dir.Size) {
            std::cerr << "[reloc] table missing\n";
            return false;
        }

        auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(util::rvaToPtr(image_, dir.VirtualAddress));
        while (reloc->SizeOfBlock) {
            auto count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto entry = reinterpret_cast<PWORD>(reloc + 1);

            for (DWORD i = 0; i < count; ++i, ++entry) {
                WORD type = *entry >> 12;
                WORD off = *entry & 0xFFF;
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    auto patch = reinterpret_cast<PULONGLONG>(
                        util::rvaToPtr(image_, reloc->VirtualAddress + off));
                    *patch += delta;
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
        }
        return true;
    }

    int callEntry() {
        auto entry = util::rvaToPtr(image_, nt_->OptionalHeader.AddressOfEntryPoint);
        if (nt_->FileHeader.Characteristics & IMAGE_FILE_DLL) {
            auto dllMain = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(entry);
            dllMain(reinterpret_cast<HINSTANCE>(image_), DLL_PROCESS_ATTACH, nullptr);
            return 0;
        }
        if (nt_->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
            auto winMain = reinterpret_cast<int (WINAPI*)(HINSTANCE, HINSTANCE, LPSTR, int)>(entry);
            return winMain(reinterpret_cast<HINSTANCE>(image_), nullptr,
                const_cast<char*>(cmd_.raw()), SW_SHOWDEFAULT);
        }
        auto mainFn = reinterpret_cast<int (*)(int, char**)>(entry);
        return mainFn(cmd_.argc(), cmd_.argv());
    }

    // ---------- members ----------
    CommandLine& cmd_;
    std::unique_ptr<FileMap>     map_;
    PIMAGE_NT_HEADERS            nt_{ nullptr };
    LPVOID                       image_{ nullptr };
    SIZE_T                       imageSize_{ 0 };
    bool                         exitCalled_{ false };
    DWORD                        exitCode_{ 0 };
};

// --------------------------------------------------
// Entry point
// --------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <pe_file> [arguments...]\n";
        return 1;
    }
    CommandLine cmd(argc, argv, 2); // skip exe + target path
    PELoader loader(cmd);
    if (!loader.load(argv[1])) return 1;
    return loader.run();
}
```
Load MUI
```cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <winnls.h>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <cstring>
#include <unordered_map>

#pragma comment(lib, "kernel32.lib")

// Delay import structures (in case SDK doesn't have them)
#ifndef IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#endif

#if (defined(_WIN32_WINNT) && _WIN32_WINNT <= 0x0601) && !defined(__MINGW32__)
#include "pshpack4.h"
typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RvaBased : 1;             // Delay load version 2
            DWORD ReservedAttributes : 31;
        } DUMMYSTRUCTNAME;
    } Attributes;

    DWORD DllNameRVA;                       // RVA to the name of the target library
    DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location
    DWORD ImportAddressTableRVA;            // RVA to the start of the IAT
    DWORD ImportNameTableRVA;               // RVA to the start of the name table
    DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
    DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
    DWORD TimeDateStamp;                    // 0 if not bound
} IMAGE_DELAYLOAD_DESCRIPTOR, * PIMAGE_DELAYLOAD_DESCRIPTOR;
#include "poppack.h"
#endif

// --------------------------------------------------
// MUI Manager for Multilingual Support
// --------------------------------------------------
class MUIManager {
public:
    MUIManager() : currentMUI_(nullptr) {
        initializeDefaultLanguage();
    }

    ~MUIManager() {
        cleanup();
    }

    bool loadLanguage(const std::wstring& languageCode) {
        HMODULE newMUI = loadMUIModule(languageCode);
        if (newMUI) {
            if (currentMUI_ && currentMUI_ != GetModuleHandleW(nullptr)) {
                FreeLibrary(currentMUI_);
            }
            currentMUI_ = newMUI;
            currentLanguage_ = languageCode;
            std::wcout << L"[MUI] Loaded language: " << languageCode << L"\n";
            return true;
        }
        return false;
    }

    std::wstring loadString(UINT resourceId) const {
        if (!currentMUI_) return L"";

        wchar_t buffer[1024];
        int result = LoadStringW(currentMUI_, resourceId, buffer, 1024);
        return result > 0 ? std::wstring(buffer) : L"";
    }

    const std::wstring& getCurrentLanguage() const {
        return currentLanguage_;
    }

    bool isLanguageAvailable(const std::wstring& languageCode) const {
        HMODULE testMUI = loadMUIModule(languageCode);
        if (testMUI) {
            FreeLibrary(testMUI);
            return true;
        }
        return false;
    }

private:
    void initializeDefaultLanguage() {
        wchar_t langBuffer[LOCALE_NAME_MAX_LENGTH];
        if (GetUserDefaultLocaleName(langBuffer, LOCALE_NAME_MAX_LENGTH)) {
            currentLanguage_ = langBuffer;
        }
        else {
            currentLanguage_ = L"en-US";
        }

        // Try to load default language MUI
        if (!loadLanguage(currentLanguage_)) {
            // Fallback to English
            if (!loadLanguage(L"en-US")) {
                // Final fallback to main module
                currentMUI_ = GetModuleHandleW(nullptr);
                currentLanguage_ = L"default";
            }
        }
    }

    HMODULE loadMUIModule(const std::wstring& languageCode) const {
        // Get current module path
        wchar_t modulePath[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) {
            return nullptr;
        }

        // Extract directory and filename
        std::wstring moduleDir = modulePath;
        size_t lastSlash = moduleDir.find_last_of(L"\\/");
        if (lastSlash == std::wstring::npos) return nullptr;

        std::wstring fileName = moduleDir.substr(lastSlash + 1);
        moduleDir = moduleDir.substr(0, lastSlash);

        // Construct MUI path: ModuleDir\LanguageCode\ModuleName.mui
        std::wstring muiPath = moduleDir + L"\\" + languageCode + L"\\" + fileName + L".mui";

        // Try to load MUI file
        return LoadLibraryExW(muiPath.c_str(), nullptr,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    }

    void cleanup() {
        if (currentMUI_ && currentMUI_ != GetModuleHandleW(nullptr)) {
            FreeLibrary(currentMUI_);
            currentMUI_ = nullptr;
        }
    }

    HMODULE currentMUI_;
    std::wstring currentLanguage_;
};

// --------------------------------------------------
// Utility
// --------------------------------------------------
namespace util {
    inline LPVOID rvaToPtr(LPVOID base, DWORD rva) {
        return static_cast<BYTE*>(base) + rva;
    }

    inline bool validatePtr(LPVOID base, SIZE_T baseSize, LPVOID ptr, SIZE_T ptrSize) {
        if (!base || !ptr || baseSize == 0 || ptrSize == 0) return false;
        auto start = reinterpret_cast<ULONG_PTR>(base);
        auto end = start + baseSize;
        auto check = reinterpret_cast<ULONG_PTR>(ptr);
        return (check >= start) && (check + ptrSize <= end);
    }

    inline std::string getLastErrorString() {
        DWORD error = GetLastError();
        if (error == 0) return "No error";

        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer, 0, nullptr);

        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);
        return message;
    }
}

// --------------------------------------------------
// RAII file‑mapping wrapper
// --------------------------------------------------
class FileMap {
public:
    explicit FileMap(const std::string& path) {
        file_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[FileMap] Cannot open " << path << " (" << util::getLastErrorString() << ")\n";
            return;
        }

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(file_, &fileSize)) {
            std::cerr << "[FileMap] GetFileSizeEx failed (" << util::getLastErrorString() << ")\n";
            return;
        }
        size_ = static_cast<DWORD>(fileSize.QuadPart);

        mapping_ = CreateFileMappingA(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_) {
            std::cerr << "[FileMap] CreateFileMapping failed (" << util::getLastErrorString() << ")\n";
            return;
        }
        view_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) {
            std::cerr << "[FileMap] MapViewOfFile failed (" << util::getLastErrorString() << ")\n";
        }
    }

    ~FileMap() {
        if (view_)    UnmapViewOfFile(view_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    }

    [[nodiscard]] bool   valid() const { return view_ != nullptr; }
    [[nodiscard]] const void* data()  const { return view_; }
    [[nodiscard]] DWORD  size()  const { return size_; }

private:
    HANDLE file_{ INVALID_HANDLE_VALUE };
    HANDLE mapping_{ nullptr };
    LPVOID view_{ nullptr };
    DWORD  size_{ 0 };
};

// --------------------------------------------------
// Command‑line helper (skips first <skip> parameters)
// --------------------------------------------------
class CommandLine {
public:
    CommandLine(int argc, char* argv[], int skip = 0) {
        for (int i = skip; i < argc; ++i) {
            args_.emplace_back(argv[i]);
        }
        buildRaw();
        buildArgv();
    }

    [[nodiscard]] int      argc() const { return static_cast<int>(args_.size()); }
    [[nodiscard]] char** argv() const { return argv_.get(); }
    [[nodiscard]] LPCSTR   raw()  const { return raw_.c_str(); }

private:
    void buildRaw() {
        for (size_t i = 0; i < args_.size(); ++i) {
            if (i) raw_ += ' ';
            const auto& s = args_[i];
            if (s.find_first_of(" \t") != std::string::npos) {
                raw_ += '"' + s + '"';
            }
            else {
                raw_ += s;
            }
        }
    }

    void buildArgv() {
        argv_ = std::make_unique<char* []>(args_.size() + 1);
        for (size_t i = 0; i < args_.size(); ++i) {
            argv_[i] = args_[i].data();
        }
        argv_[args_.size()] = nullptr; // Null terminate
    }

    std::vector<std::string> args_;
    std::string              raw_;
    std::unique_ptr<char* []> argv_;
};

// Forward decl so static hook can access loader instance
class PELoader;
static PELoader* g_loader = nullptr;

// Stub function for missing imports
static LONG_PTR WINAPI StubFunction() {
    std::cout << "[STUB] Called missing function - returning 0\n";
    return 0;
}

// --------------------------------------------------
// PE loader (single‑file, minimal OOP) with delay import support
// --------------------------------------------------
class PELoader {
private:
    bool skipMissingImports_;

public:
    explicit PELoader(CommandLine& cmd, bool skipMissingImports = false)
        : cmd_(cmd), skipMissingImports_(skipMissingImports), muiManager_(std::make_unique<MUIManager>()) {
        g_loader = this;
    }

    ~PELoader() {
        cleanup();
        g_loader = nullptr;
    }

    // Intercept ExitProcess so the host process keeps control
    static void WINAPI ExitProcessHook(UINT code) {
        if (g_loader) {
            g_loader->exitCalled_ = true;
            g_loader->exitCode_ = code;
            std::cout << "[+] ExitProcess intercepted — code=" << code << "\n";
        }
    }

    bool load(const std::string& path) {
        try {
            map_ = std::make_unique<FileMap>(path);
            if (!map_->valid()) {
                std::cerr << "[!] Failed to map file: " << path << "\n";
                return false;
            }

            if (!isValidPE(map_->data())) {
                std::cerr << "[!] Invalid PE file: " << path << "\n";
                return false;
            }

            nt_ = getNtHeaders(map_->data());
            if (!nt_) {
                std::cerr << "[!] Invalid NT headers\n";
                return false;
            }

            imageSize_ = nt_->OptionalHeader.SizeOfImage;
            if (imageSize_ == 0 || imageSize_ > 0x10000000) { // Sanity check
                std::cerr << "[!] Invalid image size: " << imageSize_ << "\n";
                return false;
            }

            image_ = allocateImage(nt_);
            if (!image_) {
                std::cerr << "[!] Failed to allocate image memory\n";
                return false;
            }

            if (!copyImage()) {
                std::cerr << "[!] Failed to copy image\n";
                return false;
            }

            nt_ = getNtHeaders(image_);

            if (!resolveImports()) {
                std::cerr << "[!] Failed to resolve imports\n";
                return false;
            }

            if (!resolveDelayImports()) {
                std::cerr << "[!] Failed to resolve delay imports\n";
                return false;
            }

            if (!applyRelocations()) {
                std::cerr << "[!] Failed to apply relocations\n";
                return false;
            }

            // Try to load MUI resources for the loaded PE
            loadMUIResources(path);

            std::cout << "[+] PE loaded successfully at: " << std::hex << image_ << std::dec << "\n";
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "[!] Exception during load: " << e.what() << "\n";
            return false;
        }
    }

    int run() {
        if (!image_) {
            std::cerr << "[!] No image loaded\n";
            return -1;
        }

        try {
            return callEntry();
        }
        catch (const std::exception& e) {
            std::cerr << "[!] Exception during execution: " << e.what() << "\n";
            return -1;
        }
    }

    // MUI related functions
    bool setLanguage(const std::wstring& languageCode) {
        bool result = muiManager_->loadLanguage(languageCode);
        if (!result) {
            std::wcout << L"[!] MUI file not found for language: " << languageCode << L" (continuing without MUI)\n";
        }
        return result;
    }

    std::wstring getString(UINT resourceId) const {
        return muiManager_->loadString(resourceId);
    }

private:
    // ---------- helpers ----------
    static bool isValidPE(const void* data) {
        if (!data) return false;

        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > 0x1000) {
            return false;
        }

        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const BYTE*>(data) + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE;
    }

    static PIMAGE_NT_HEADERS getNtHeaders(const void* base) {
        if (!base) return nullptr;

        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        return reinterpret_cast<PIMAGE_NT_HEADERS>(
            static_cast<BYTE*>(const_cast<void*>(base)) + dos->e_lfanew);
    }

    LPVOID allocateImage(PIMAGE_NT_HEADERS nt) {
        if (!nt) return nullptr;

        SIZE_T sz = nt->OptionalHeader.SizeOfImage;
        auto preferred = reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase);

        // Try preferred address first
        auto mem = VirtualAlloc(preferred, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem) {
            std::cout << "[+] Allocated at preferred address: " << std::hex << mem << std::dec << "\n";
            return mem;
        }

        // Fallback to any address
        mem = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem) {
            std::cout << "[+] Allocated at alternate address: " << std::hex << mem << std::dec << "\n";
        }
        return mem;
    }

    bool copyImage() {
        if (!image_ || !map_ || !nt_) return false;

        // Copy headers
        SIZE_T headerSize = nt_->OptionalHeader.SizeOfHeaders;
        if (headerSize > map_->size()) {
            std::cerr << "[!] Invalid header size\n";
            return false;
        }

        std::memcpy(image_, map_->data(), headerSize);

        // Copy sections
        auto section = IMAGE_FIRST_SECTION(nt_);
        for (int i = 0; i < nt_->FileHeader.NumberOfSections; ++i, ++section) {
            if (!section->SizeOfRawData) continue;

            if (section->PointerToRawData + section->SizeOfRawData > map_->size()) {
                std::cerr << "[!] Invalid section data\n";
                return false;
            }

            if (section->VirtualAddress + section->SizeOfRawData > imageSize_) {
                std::cerr << "[!] Section exceeds image size\n";
                return false;
            }

            std::memcpy(util::rvaToPtr(image_, section->VirtualAddress),
                static_cast<const BYTE*>(map_->data()) + section->PointerToRawData,
                section->SizeOfRawData);
        }
        return true;
    }

    bool resolveImports() {
        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.Size) {
            std::cout << "[+] No imports to resolve\n";
            return true;
        }

        if (!util::validatePtr(image_, imageSize_,
            util::rvaToPtr(image_, dir.VirtualAddress), dir.Size)) {
            std::cerr << "[!] Invalid import directory\n";
            return false;
        }

        auto imp = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            util::rvaToPtr(image_, dir.VirtualAddress));

        while (imp->Name) {
            if (!util::validatePtr(image_, imageSize_, imp, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
                std::cerr << "[!] Invalid import descriptor\n";
                return false;
            }

            const char* dllName = reinterpret_cast<char*>(util::rvaToPtr(image_, imp->Name));
            if (!util::validatePtr(image_, imageSize_, const_cast<char*>(dllName), 1)) {
                std::cerr << "[!] Invalid DLL name\n";
                return false;
            }

            std::cout << "[+] Loading DLL: " << dllName << "\n";
            HMODULE dll = LoadLibraryA(dllName);
            if (!dll) {
                std::cerr << "[!] Cannot load " << dllName << " (" << util::getLastErrorString() << ")\n";
                return false;
            }

            auto thunkName = reinterpret_cast<PIMAGE_THUNK_DATA>(
                util::rvaToPtr(image_, imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto thunkIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(util::rvaToPtr(image_, imp->FirstThunk));

            while (thunkName->u1.AddressOfData) {
                if (!util::validatePtr(image_, imageSize_, thunkName, sizeof(IMAGE_THUNK_DATA)) ||
                    !util::validatePtr(image_, imageSize_, thunkIAT, sizeof(IMAGE_THUNK_DATA))) {
                    std::cerr << "[!] Invalid thunk data\n";
                    return false;
                }

                FARPROC func = nullptr;
                std::string funcName;

                if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal)) {
                    DWORD ordinal = static_cast<DWORD>(IMAGE_ORDINAL(thunkName->u1.Ordinal));
                    func = GetProcAddress(dll, MAKEINTRESOURCEA(ordinal));
                    funcName = "Ordinal " + std::to_string(ordinal);
                }
                else {
                    auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        util::rvaToPtr(image_, thunkName->u1.AddressOfData));

                    if (!util::validatePtr(image_, imageSize_, ibn, sizeof(IMAGE_IMPORT_BY_NAME))) {
                        std::cerr << "[!] Invalid import by name\n";
                        return false;
                    }

                    funcName = ibn->Name;
                    if (std::strcmp("ExitProcess", ibn->Name) == 0) {
                        func = reinterpret_cast<FARPROC>(&ExitProcessHook);
                    }
                    else {
                        func = GetProcAddress(dll, ibn->Name);
                    }
                }

                if (!func) {
                    std::cerr << "[!] Failed to resolve function: " << funcName
                        << " from " << dllName << " (" << util::getLastErrorString() << ")\n";

                    if (skipMissingImports_ ||
                        (std::string(dllName).find("COMCTL32") != std::string::npos &&
                            funcName.find("Ordinal") != std::string::npos)) {

                        std::cerr << "[+] Using stub function for missing import: " << funcName << "\n";
                        thunkIAT->u1.Function = reinterpret_cast<ULONGLONG>(&StubFunction);
                    }
                    else {
                        return false;
                    }
                }
                else {
                    thunkIAT->u1.Function = reinterpret_cast<ULONGLONG>(func);
                }
                ++thunkName; ++thunkIAT;
            }
            ++imp;
        }

        std::cout << "[+] Imports resolved successfully\n";
        return true;
    }

    bool resolveDelayImports() {
        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (!dir.Size) {
            std::cout << "[+] No delay imports to resolve\n";
            return true;
        }

        std::cout << "[+] Processing delay imports...\n";

        if (!util::validatePtr(image_, imageSize_,
            util::rvaToPtr(image_, dir.VirtualAddress), dir.Size)) {
            std::cerr << "[!] Invalid delay import directory\n";
            return false;
        }

        auto desc = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(
            util::rvaToPtr(image_, dir.VirtualAddress));

        while (desc->DllNameRVA) {
            if (!util::validatePtr(image_, imageSize_, desc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) {
                std::cerr << "[!] Invalid delay import descriptor\n";
                return false;
            }

            // Get DLL name
            ULONGLONG imageBase = nt_->OptionalHeader.ImageBase;
            DWORD dllNameRva = desc->DllNameRVA;
            if (dllNameRva > imageBase) {
                dllNameRva = static_cast<DWORD>(dllNameRva - imageBase); // Convert VA to RVA if needed
            }

            const char* dllName = reinterpret_cast<const char*>(util::rvaToPtr(image_, dllNameRva));
            if (!util::validatePtr(image_, imageSize_, const_cast<char*>(dllName), 1)) {
                std::cerr << "[!] Invalid DLL name in delay import\n";
                return false;
            }

            std::cout << "[+] Processing delay import DLL: " << dllName << "\n";

            // Process delay import functions
            bool success = false;
#ifdef _WIN64
            success = processDelayImport<ULONGLONG, IMAGE_THUNK_DATA64>(
                desc, dllName, imageBase, IMAGE_ORDINAL_FLAG64);
#else
            success = processDelayImport<DWORD, IMAGE_THUNK_DATA32>(
                desc, dllName, imageBase, IMAGE_ORDINAL_FLAG32);
#endif
            if (!success) {
                std::cerr << "[!] Failed to process delay imports for " << dllName << "\n";
                return false;
            }

            ++desc;
        }

        std::cout << "[+] Delay imports resolved successfully\n";
        return true;
    }

    template<typename T_FIELD, typename T_IMAGE_THUNK_DATA>
    bool processDelayImport(PIMAGE_DELAYLOAD_DESCRIPTOR desc, const char* dllName,
        ULONGLONG imageBase, T_FIELD ordinalFlag) {

        // Load the DLL
        HMODULE dll = LoadLibraryA(dllName);
        if (!dll) {
            std::cerr << "[!] Cannot load delay import DLL: " << dllName
                << " (" << util::getLastErrorString() << ")\n";
            return false;
        }

        // Get RVAs
        DWORD iatRva = desc->ImportAddressTableRVA;
        if (iatRva > imageBase) iatRva = static_cast<DWORD>(iatRva - imageBase);

        DWORD thunkRva = desc->ImportNameTableRVA;
        if (thunkRva > imageBase) thunkRva = static_cast<DWORD>(thunkRva - imageBase);

        // Get pointers to tables
        auto iatPtr = reinterpret_cast<T_FIELD*>(util::rvaToPtr(image_, iatRva));
        auto thunkPtr = reinterpret_cast<T_IMAGE_THUNK_DATA*>(util::rvaToPtr(image_, thunkRva));

        // Process each function
        while (*iatPtr && thunkPtr->u1.AddressOfData) {
            if (!util::validatePtr(image_, imageSize_, iatPtr, sizeof(T_FIELD)) ||
                !util::validatePtr(image_, imageSize_, thunkPtr, sizeof(T_IMAGE_THUNK_DATA))) {
                std::cerr << "[!] Invalid delay import thunk\n";
                return false;
            }

            FARPROC func = nullptr;

            // Check if import by ordinal
            if (thunkPtr->u1.Ordinal & ordinalFlag) {
                T_FIELD ordinal = thunkPtr->u1.Ordinal & (~ordinalFlag);
                func = GetProcAddress(dll, MAKEINTRESOURCEA(static_cast<DWORD>(ordinal)));
            }
            else {
                // Import by name
                DWORD nameRva = static_cast<DWORD>(thunkPtr->u1.AddressOfData);
                if (nameRva > imageBase) nameRva = static_cast<DWORD>(nameRva - imageBase);

                auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(util::rvaToPtr(image_, nameRva));
                if (!util::validatePtr(image_, imageSize_, ibn, sizeof(IMAGE_IMPORT_BY_NAME))) {
                    std::cerr << "[!] Invalid import by name structure\n";
                    return false;
                }

                const char* funcName = reinterpret_cast<const char*>(ibn->Name);
                if (std::strcmp("ExitProcess", funcName) == 0) {
                    func = reinterpret_cast<FARPROC>(&ExitProcessHook);
                }
                else {
                    func = GetProcAddress(dll, funcName);
                }
            }

            if (!func) {
                std::cerr << "[!] Failed to resolve delay import function\n";
                if (skipMissingImports_) {
                    std::cerr << "[+] Using stub function for missing delay import\n";
                    *iatPtr = reinterpret_cast<T_FIELD>(&StubFunction);
                }
                else {
                    return false;
                }
            }
            else {
                // Directly patch the IAT
                *iatPtr = reinterpret_cast<T_FIELD>(func);
            }

            ++iatPtr;
            ++thunkPtr;
        }

        return true;
    }

    bool applyRelocations() {
        ULONGLONG delta = reinterpret_cast<ULONGLONG>(image_) - nt_->OptionalHeader.ImageBase;
        if (!delta) {
            std::cout << "[+] No relocations needed (loaded at preferred address)\n";
            return true;
        }

        const auto& dir = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!dir.Size) {
            std::cerr << "[!] Relocation table missing but required\n";
            return false;
        }

        if (!util::validatePtr(image_, imageSize_,
            util::rvaToPtr(image_, dir.VirtualAddress), dir.Size)) {
            std::cerr << "[!] Invalid relocation directory\n";
            return false;
        }

        auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            util::rvaToPtr(image_, dir.VirtualAddress));

        while (reloc->SizeOfBlock) {
            if (!util::validatePtr(image_, imageSize_, reloc, sizeof(IMAGE_BASE_RELOCATION))) {
                std::cerr << "[!] Invalid relocation block\n";
                return false;
            }

            auto count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto entry = reinterpret_cast<PWORD>(reloc + 1);

            for (DWORD i = 0; i < count; ++i, ++entry) {
                WORD type = *entry >> 12;
                WORD off = *entry & 0xFFF;

                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    auto patch = reinterpret_cast<PULONGLONG>(
                        util::rvaToPtr(image_, reloc->VirtualAddress + off));

                    if (!util::validatePtr(image_, imageSize_, patch, sizeof(ULONGLONG))) {
                        std::cerr << "[!] Invalid relocation target\n";
                        return false;
                    }

                    *patch += delta;
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
        }

        std::cout << "[+] Relocations applied (delta: " << std::hex << delta << std::dec << ")\n";
        return true;
    }

    void loadMUIResources(const std::string& path) {
        // Extract filename without extension for MUI loading
        size_t lastSlash = path.find_last_of("\\/");
        size_t lastDot = path.find_last_of('.');

        if (lastSlash != std::string::npos && lastDot != std::string::npos && lastDot > lastSlash) {
            std::string baseName = path.substr(lastSlash + 1, lastDot - lastSlash - 1);

            // Convert to wide string for MUI operations
            std::wstring wBaseName(baseName.begin(), baseName.end());

            std::wcout << L"[MUI] Attempting to load resources for: " << wBaseName << L"\n";

            // Try current system language first
            wchar_t langBuffer[LOCALE_NAME_MAX_LENGTH];
            if (GetUserDefaultLocaleName(langBuffer, LOCALE_NAME_MAX_LENGTH)) {
                if (muiManager_->isLanguageAvailable(langBuffer)) {
                    muiManager_->loadLanguage(langBuffer);
                }
            }
        }
    }

    int callEntry() {
        if (!nt_ || !image_) return -1;

        auto entry = util::rvaToPtr(image_, nt_->OptionalHeader.AddressOfEntryPoint);
        if (!entry) {
            std::cerr << "[!] Invalid entry point\n";
            return -1;
        }

        std::cout << "[+] Calling entry point at: " << std::hex << entry << std::dec << "\n";

        if (nt_->FileHeader.Characteristics & IMAGE_FILE_DLL) {
            auto dllMain = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(entry);
            BOOL result = dllMain(reinterpret_cast<HINSTANCE>(image_), DLL_PROCESS_ATTACH, nullptr);
            return result ? 0 : -1;
        }

        if (nt_->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
            auto winMain = reinterpret_cast<int (WINAPI*)(HINSTANCE, HINSTANCE, LPSTR, int)>(entry);
            return winMain(reinterpret_cast<HINSTANCE>(image_), nullptr,
                const_cast<char*>(cmd_.raw()), SW_SHOWDEFAULT);
        }

        auto mainFn = reinterpret_cast<int (*)(int, char**)>(entry);
        return mainFn(cmd_.argc(), cmd_.argv());
    }

    void cleanup() {
        if (image_) {
            VirtualFree(image_, 0, MEM_RELEASE);
            image_ = nullptr;
        }
    }

    // ---------- members ----------
    CommandLine& cmd_;
    std::unique_ptr<FileMap>     map_;
    std::unique_ptr<MUIManager>  muiManager_;
    PIMAGE_NT_HEADERS            nt_{ nullptr };
    LPVOID                       image_{ nullptr };
    SIZE_T                       imageSize_{ 0 };
    bool                         exitCalled_{ false };
    DWORD                        exitCode_{ 0 };
};

// --------------------------------------------------
// Entry point
// --------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <pe_file> [arguments...]\n";
        std::cout << "Options:\n";
        std::cout << "  --lang <code>     Set language (e.g., en-US, vi-VN)\n";
        return 1;
    }

    // Parse command line arguments
    std::string targetFile = argv[1];
    std::wstring language;

    // Check for language option
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "--lang" && i + 1 < argc) {
            std::string langStr = argv[i + 1];
            language = std::wstring(langStr.begin(), langStr.end());
            // Remove language arguments from command line
            for (int j = i; j < argc - 2; ++j) {
                argv[j] = argv[j + 2];
            }
            argc -= 2;
            break;
        }
    }

    CommandLine cmd(argc, argv, 2); // skip exe + target path
    PELoader loader(cmd);

    // Set language if specified
    if (!language.empty()) {
        if (loader.setLanguage(language)) {
            std::wcout << L"[+] Language set to: " << language << L"\n";
        }
        // Continue execution even if MUI loading fails
    }

    if (!loader.load(targetFile)) {
        std::cerr << "[!] Failed to load PE file: " << targetFile << "\n";
        return 1;
    }

    std::cout << "[+] Starting execution...\n";
    return loader.run();
}

```

