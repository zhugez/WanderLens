# Blog Tag Standards

## Standardized Tags

### Windows Internals
- `WindowsInternals` - General Windows internals content
- `KernelMode` - Kernel-mode programming and concepts
- `MemoryManagement` - Memory management internals
- `ProcessInternals` - Process/Thread structures
- `SystemCalls` - System call mechanisms

### Exploitation & Security Research
- `KernelExploitation` - Kernel vulnerability exploitation
- `PrivilegeEscalation` - Privilege escalation techniques
- `DKOM` - Direct Kernel Object Manipulation
- `VulnResearch` - Vulnerability research
- `CVEAnalysis` - CVE deep dives

### Malware & Red Team
- `MalwareDev` - Malware development techniques
- `RedTeam` - Red team operations and tools
- `Evasion` - EDR/AV evasion techniques
- `PELoading` - PE loading and injection
- `Persistence` - Persistence mechanisms

### CTF & Writeups
- `Writeup` - CTF/Box writeups
- `CTF` - CTF-specific content
- `HTB` - HackTheBox challenges
- `PWN` - Binary exploitation challenges

### Tools & Techniques
- `Reversing` - Reverse engineering
- `Debugging` - Debugging techniques
- `Forensics` - Digital forensics

## Tag Usage Examples

### Windows Internals Posts
```yaml
tags: ["WindowsInternals", "KernelMode", "SystemCalls"]
```

### Exploitation Posts
```yaml
tags: ["KernelExploitation", "PrivilegeEscalation", "DKOM"]
```

### Malware Development Posts
```yaml
tags: ["MalwareDev", "Evasion", "PELoading"]
```

### CVE Analysis Posts
```yaml
tags: ["VulnResearch", "CVEAnalysis", "KernelExploitation"]
```

### CTF Writeups
```yaml
tags: ["Writeup", "CTF", "PWN"]
```

## Applied Tags (Current Posts)

### ✅ Chuẩn hoá rồi:
1. **WindowsArchitectureDeepDive** - `["WindowsInternals", "KernelMode", "SystemCalls"]`
2. **WindowsMemoryManagement** - `["WindowsInternals", "MemoryManagement", "KernelExploitation"]`
3. **ProcessThreadInternals** - `["WindowsInternals", "ProcessInternals", "PrivilegeEscalation", "DKOM"]`
4. **MeterpreterLifeCycle** - `["WindowsInternals", "RedTeam", "MalwareDev"]`

### 🔄 Cần chuẩn hoá:
5. **CVE2024_21338** → `["VulnResearch", "CVEAnalysis", "PrivilegeEscalation"]`
6. **RemoteDesktopAppExploit** → `["VulnResearch", "PrivilegeEscalation", "Persistence"]`
7. **SelfDelete** → `["WindowsInternals", "MalwareDev", "Evasion"]`
8. **SlicetheStackSpottheBug** → `["RedTeam", "Research"]`
9. **JuniorHackingTalentsCTF_writeup** → `["Writeup", "CTF"]`
10. **Rootme_writeup** → `["Writeup", "Reversing"]`
11. **Pwnable.kr_writeup** → `["Writeup", "PWN"]`
12. **Devguru**, **Hackid101**, **Nullbyte**, **Photographer** → `["Writeup", "HTB"]`

### ⚠️ Posts cần thêm tags (hiện tại empty):
- BinaryClass
- callbackfunction
- Dropper
- RemoteInjectPE
- RunPEInWindows1124H2
- TheDarkArtsofPELoadinginWindows

## Rules

1. **Max 3-4 tags per post** - Không quá nhiều
2. **CamelCase** - WindowsInternals, not windows-internals
3. **No spaces** - MalwareDev, not Malware Dev
4. **Specific over generic** - ProcessInternals > WindowsInternals
5. **Consistent naming** - Always same spelling

## Migration Script

```bash
# To apply these changes to all posts, run:
# python scripts/migrate-tags.py
```
