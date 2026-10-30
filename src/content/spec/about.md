## About

I'm Yasna. I take Windows apart in a debugger and write down what I find.

22 posts, going back to 2021. They are long, and they assume you want the mechanism rather than a summary of it. The PE loading post walks manual mapping from the PEB through fixing the IAT and relocations, parameter hijacking, and execution strategy, and ends with a working proof of concept. The CVE-2024-21338 post analyses `appid.sys` and its IOCTL surface, then works through SMEP and kCFG before the demo. The memory post runs from four-level paging to VAD trees to the PFN database to paged and non-paged pools, with the WinDbg session printed alongside each step. The Meterpreter post goes through metsrv, the TLV protocol, transports, the extension model, and the session lifecycle.

Around those: a self-deleting binary built on `FileRenameInfo` and `FileDispositionInfo`, token theft through `DuplicateTokenEx` and named-pipe impersonation, DKOM, thread injection, four practice machines from the Pentesting Diary series, and CTF writeups for pwnable.kr, Root-Me and Junior Hacking Talents.

Everything is in the [archive](/archive/), written in Vietnamese or English.

Elsewhere: [GitHub](https://github.com/zhugez) · [X](https://twitter.com/dezzhu1) · [LinkedIn](https://www.linkedin.com/in/dezzhu/) · [Facebook](https://facebook.com/dezzhu.info)

<sub>Avatar art: [星と少女](https://www.pixiv.net/artworks/108916539) by [Stella](https://www.pixiv.net/users/93273965). Other theme imagery: [Unsplash](https://unsplash.com/), [Civitai](https://civitai.com/posts/586908).</sub>
