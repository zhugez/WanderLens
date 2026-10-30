## About

I'm Yasna. I write about Windows internals and security research.

Most posts follow the same shape: describe a structure, show it on a live machine in a debugger, then do something with it. The process and thread post walks `_EPROCESS`, `_KTHREAD` and the token, prints them with `!process` in WinDbg, then abuses the token through `DuplicateTokenEx` and named-pipe impersonation, and closes on DKOM and thread injection. The memory post covers 4-level paging, VAD trees, the PFN database and paged versus non-paged pools, with the `kd>` output sitting next to each explanation.

What's in the archive:

- **Windows internals** — process and thread structures, virtual memory and page tables, user mode versus kernel mode, callback functions, self-deletion through `FileRenameInfo` and `FileDispositionInfo`
- **Exploitation** — CVE-2024-21338, admin to kernel; loading a PE into a remote process; a dropper written in C++
- **Malware analysis** — the Meterpreter lifecycle, from stager to in-memory session
- **Pentesting Diary** — four practice machines: Hack kid 1.0.1, Photographer, Dev Guru, NullByte
- **CTF writeups** — pwnable.kr, Root-Me, Junior Hacking Talents
- **Tooling** — wiring `CLIPROXYAPI` into Claude Code

Posts are written in Vietnamese or English. Everything since 2021 is in the [archive](/archive/).

Elsewhere: [GitHub](https://github.com/zhugez) · [X](https://twitter.com/dezzhu1) · [LinkedIn](https://www.linkedin.com/in/dezzhu/) · [Facebook](https://facebook.com/dezzhu.info)

> ### Image credits
> - [Unsplash](https://unsplash.com/)
> - [星と少女](https://www.pixiv.net/artworks/108916539) by [Stella](https://www.pixiv.net/users/93273965)
> - [Rabbit - v1.4 Showcase](https://civitai.com/posts/586908) by [Rabbit_YourMajesty](https://civitai.com/user/Rabbit_YourMajesty)
