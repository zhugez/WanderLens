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