# 🚩 CTF Write-ups & Binary Analysis Archive
<p align="left">
  <img src="https://img.shields.io/badge/Focus-Reverse%20Engineering%20%7C%20Defensive%20Security-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Handle-Argenvale-green?style=flat-square" />
  <img src="https://img.shields.io/badge/Platform-Root--Me%20%7C%20CTFtime-orange?style=flat-square" />
</p>

Welcome to my central repository for **Capture The Flag (CTF)** walkthroughs and technical write-ups. This archive documents my hands-on methodology in dissecting challenges, focusing primarily on **Reverse Engineering**, **Binary Analysis**, and **System Forensics**.

Rather than simply archiving solutions, each write-up emphasizes **root-cause analysis**, **assembly logic decompilation**, and **threat actor emulation**.

---

## 🔍 Write-up Framework

To align with real-world Incident Response (IR) and SOC Triage standards, each write-up follows a structured **4-stage documentation methodology**:

1. **Reconnaissance:** Perform initial binary and network profiling using tools such as `file`, `strings`, and PE/ELF header analysis.

2. **Static Analysis:** Analyze disassembly and decompiled code in Ghidra to map program logic and identify sensitive APIs.

3. **Dynamic Verification:** Use x64dbg / GDB for live debugging to monitor register states, memory allocation, and execution flow.

4. **Defender's Takeaway (SOC Lens):** Identify Indicators of Compromise (IoCs) and explain how the vulnerability or malware can be detected on enterprise endpoints.


---


## 🛠️ Core Toolset

### 🔍 Static Analysis
- **Decompilers:** Ghidra (Primary), IDA Free.
- **Binary Utilities:** `file`, `strings`, `objdump`, `nm`.
- **Format Inspection:** Detect It Easy (DIE).

### ⚙️ Dynamic Analysis & Debugging
- **Linux Debugging:** GDB (with GEF/Pwndbg), `ltrace`, `strace`.
- **Windows Debugging:** x64dbg (x32/x64).
- **Environment:** Wine (Running PE binaries on Linux), VirtualBox.

### 🛡️ Security & Mitigation Checks
- **Exploitation:** `checksec`, `ROPgadget`.
- **Packer Identification:** `binwalk`, `UPX`.

### 🌐 System & Network Monitoring
- **Tools:** Wireshark, Sysinternals Suite (Procmon, Procexp).

---


### ⚠️ Disclaimer

All write-ups, code snippets, and solutions in this repository are intended for educational purposes and cybersecurity skill development. All challenges are solved within authorized CTF environments. The content is provided for learning and reference purposes only and should not be used for unauthorized activities.

Some write-ups may have been refined or edited with the assistance of AI tools for clarity and readability.

---


<p align="center">
<i>Maintained with dedication by <b>Argenvale</b>.</i><br>
<a href="https://github.com/DangLamMyKhanh">Return to GitHub Profile</a> • <a href="https://www.linkedin.com/in/my-khanh-dang-lam">Connect on LinkedIn</a>
</p>
