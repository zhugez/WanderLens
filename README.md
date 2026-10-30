# WanderLens

A blog about Windows internals and security research. 22 posts, 2021 to now.

[**Read it**](https://wanderlens.vercel.app) · [**Archive**](https://wanderlens.vercel.app/archive/) · [**About**](https://wanderlens.vercel.app/about/)

## What's in it

Most posts follow the same shape: describe a structure, show it on a live machine in a debugger, then do something with it. That means `kd>` output and source snippets next to the explanation, not a summary of it. Posts are written in Vietnamese or English.

**Windows internals.** Process and thread structures (`EPROCESS`, `KTHREAD`), virtual memory and page tables, user mode versus kernel mode, callback functions, and a self-deleting binary built on `FileRenameInfo` and `FileDispositionInfo` over NTFS alternate data streams.

**Kernel privilege escalation.** A writeup of CVE-2024-21338, taking an admin session to kernel mode.

**PE loading and code injection.** Loading a PE into a remote process, the loader mechanics behind it, and a dropper written in C++.

**Malware analysis.** A walkthrough of the Meterpreter lifecycle, from stager to in-memory session.

**Pentesting Diary.** Four writeups of practice machines — Hack kid 1.0.1, Photographer, Dev Guru, NullByte.

**CTF and debugging.** pwnable.kr, Root-Me, Junior Hacking Talents, and a stack-based exercise that starts from registers and ends at a root cause.

**Tooling.** Wiring `CLIPROXYAPI` into Claude Code.

Posts are filed under three categories: Cybersecurity (20), Developing (1), Tutorial (1). Tag vocabulary is defined in [`TAG_STANDARDS.md`](TAG_STANDARDS.md).

## Stack

Astro 5 · Svelte 5 · Tailwind 3 · KaTeX · Pagefind · Swup · Biome · pnpm

The theme is [Fuwari](https://github.com/saicaca/fuwari) by [saicaca](https://github.com/saicaca), MIT licensed. Search is indexed at build time by Pagefind, math is rendered by KaTeX through `remark-math` and `rehype-katex`, and page navigation is handled by Swup.

## Running locally

Requires Node.js 20+ and pnpm.

```bash
pnpm install
pnpm dev            # http://localhost:4321
```

Other scripts:

```bash
pnpm build          # astro build, then build the Pagefind index
pnpm preview        # serve the production build
pnpm type-check     # tsc --noEmit
pnpm lint           # biome check
pnpm format         # biome format --write
```

## Writing a post

```bash
pnpm new-post <slug>
```

That creates `src/content/posts/<slug>/index.md`. Frontmatter:

```yaml
---
title: "Post title"
published: 2026-01-22
description: ""
image: ""
tags: ["WindowsInternals"]
category: "Cybersecurity"
draft: false
lang: "en"
---
```

Images sit in the same directory as the post. `draft: true` keeps a post out of the build.

## Deployment

The site is deployed on Vercel. `vercel.json` is empty, so the defaults apply: `pnpm build` produces `dist/`, which Vercel serves as static output. Nothing else needs configuring.

## License

Code: [MIT](LICENSE).

Posts and images: © the author, all rights reserved. The Fuwari theme is MIT licensed and its own license applies to the theme code.
