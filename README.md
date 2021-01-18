# awesome-bugs
A collection of software bug types and articles showcasing the hunt for and exploitation of them.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)


# Bug Types
* [Command Injection](#command-injection)
* [Double Free](#double-free)
* [NULL Pointer Dereference](#null-pointer-dereference)
* [Type Confusion](#type-confusion)
* [Unexpected Sign Extension](#unexpected-sign-extension)
* [Use After Free](#use-after-free)
* [Use of Externally-Controlled Format String](#use-of-externally-controlled-format-string)
* [Write-What-Where](#write-what-where)


## Command Injection
[CWE-78](https://cwe.mitre.org/data/definitions/78.html): Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

> *"The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Pedro Ribeiro, Radek Domanski | Zero Day Initiative / Flashback Team | [CVE-2018-8460: Exposing a double free in Internet Explorer for code execution](https://www.thezdi.com/blog/2020/4/6/exploiting-the-tp-link-archer-c7-at-pwn2own-tokyo) - ([YouTube version](https://www.youtube.com/watch?v=zjafMP7EgEA)) |
| Lucas Tay | Star Labs | [Analysis & Exploitation of a Recent TP-Link Archer A7 Vulnerability](https://starlabs.sg/blog/2020/10/analysis-exploitation-of-a-recent-tp-link-archer-a7-vulnerability/) |
| David Yesland | Rhino Security Labs | [Exploiting CVE-2018-1335: Command Injection in Apache Tika](https://rhinosecuritylabs.com/application-security/exploiting-cve-2018-1335-apache-tika/) |
| Shaun Mirani | Independent Security Evaluators (ISE) | [Show Mi The Vulns: Exploiting Command Injection in Mi Router 3](https://blog.securityevaluators.com/show-mi-the-vulns-exploiting-command-injection-in-mi-router-3-55c6bcb48f09) |


## Double Free
[CWE-415](https://cwe.mitre.org/data/definitions/415.html): Double Free

> *"The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Simon Zuckerbraun | Zero Day Initiative | [CVE-2018-8460: Exposing a double free in Internet Explorer for code execution](https://www.thezdi.com/blog/2018/10/18/cve-2018-8460-exposing-a-double-free-in-internet-explorer-for-code-execution) |
| Jinwook Shin | Microsoft Security Response Center | [MS13-068: A difficult-to-exploit double free in Outlook](https://msrc-blog.microsoft.com/2013/09/10/ms13-068-a-difficult-to-exploit-double-free-in-outlook/) |
| Arthur Gerkis | Exodus Intelligence | [Pwn2Own 2019: Microsoft Edge Renderer Exploitation (CVE-2019-0940)](https://blog.exodusintel.com/2019/05/19/pwn2own-2019-microsoft-edge-renderer-exploitation-cve-2019-9999-part-1/) |
| Andrey Konovalov | Andrey Konovalov's Blog | [CVE-2016-2384: Exploiting a double-free in the USB-MIDI Linux kernel driver](https://xairy.github.io/blog/2016/cve-2016-2384) |


## NULL Pointer Dereference
[CWE-476](https://cwe.mitre.org/data/definitions/476.html): NULL Pointer Dereference

> *"A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Leeqwind | xiaodaozhi | [Win32k NULL-Pointer-Dereference Analysis by Matching the May Update](https://xiaodaozhi.com/exploit/156.html) |
| Sam Brown | MWR Labs / F-Secure | [PDF] [Windows Kernel Exploitation 101: Exploiting CVE-2014-4113](https://labs.f-secure.com/assets/BlogFiles/mwri-lab-exploiting-cve-2014-4113.pdf) |


## Type Confusion
[CWE-843](https://cwe.mitre.org/data/definitions/843.html): Access of Resource Using Incompatible Type ('Type Confusion')

> *"The program allocates or initializes a resource such as a pointer, object, or variable using one type, but it later accesses that resource using a type that is incompatible with the original type."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Man Yue Mo | GitHub Security Lab| [Ghostscript type confusion: Using variant analysis to find vulnerabilities](https://securitylab.github.com/research/ghostscript-type-confusion) |
| David Wells | Tenable | [Exploiting a Webroot Type Confusion Bug](https://medium.com/tenable-techblog/exploiting-a-webroot-type-confusion-bug-215308145e32) |
| Natalie Silvanovich | Google Project Zero | [One Perfect Bug: Exploiting Type Confusion in Flash](https://googleprojectzero.blogspot.com/2015/07/one-perfect-bug-exploiting-type_20.html) |
| The ZDI Research Team | Zero Day Initiative | [CVE-2018-12794: Using Type Confusion to Get Code Execution in Adobe Reader](https://www.thezdi.com/blog/2018/9/18/cve-2018-12794-using-type-confusion-to-get-code-execution-in-adobe-reader) |
| Microsoft Defender ATP Research Team | Microsoft | [Understanding type confusion vulnerabilities: CVE-2015-0336](https://www.microsoft.com/security/blog/2015/06/17/understanding-type-confusion-vulnerabilities-cve-2015-0336/?source=mmpc) |
| Mark Dowd, Ryan Smith, David Dewey | Black Hat USA 2009 | [Attacking Interoperability](http://hustlelabs.com/stuff/bh2009_dowd_smith_dewey.pdf) |
| Max Van Amerongen | F-Secure | [Exploiting CVE-2019-17026 - A Firefox JIT Bug](https://labs.f-secure.com/blog/exploiting-cve-2019-17026-a-firefox-jit-bug/) |
| Nils Emmerich | ERNW | [Java Buffer Overflow with ByteBuffer (CVE-2020-2803) and Mutable MethodType (CVE-2020-2805) Sandbox Escapes](https://insinuator.net/2020/09/java-buffer-overflow-with-bytebuffer-cve-2020-2803-and-mutable-methodtype-cve-2020-2805-sandbox-escapes/) |
| Max Van Amerongen | F-Secure | [Exploiting CVE-2019-17026 - A Firefox JIT Bug](https://labs.f-secure.com/blog/exploiting-cve-2019-17026-a-firefox-jit-bug/) |
| Yuki Chen | Qihoo 360 Vulcan Team | [When GC Triggers Callback](https://paper.seebug.org/1032/#case-3-type-confusion-in-jit-engine) |


## Unexpected Sign Extension
[CWE-194](https://cwe.mitre.org/data/definitions/194.html): Unexpected Sign Extension

> *"The software performs an operation on a number that causes it to be sign extended when it is transformed into a larger data type. When the original number is negative, this can produce unexpected values that lead to resultant weaknesses."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Kim Youngsung | LINE Engineering | [Buffer overflow in PJSIP, a VoIP open source library](https://engineering.linecorp.com/en/blog/buffer-overflow-in-pjsip-a-voip-open-source-library/) |


## Use After Free
[CWE-416](https://cwe.mitre.org/data/definitions/416.html): Use After Free

> *"Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Abdul-Aziz Hariri | Zero Day Initiative | [Use-After-Silence: Exploiting a Quietly Patched UAF in VMWare](https://www.thezdi.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware) |


## Use of Externally-Controlled Format String
[CWE-134](https://cwe.mitre.org/data/definitions/134.html): Use of Externally-Controlled Format String

> *"The software uses a function that accepts a format string as an argument, but the format string originates from an external source."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Joe Giron | Gironsec | [Exploit in Skyrim](https://www.gironsec.com/blog/2013/05/exploit-in-skyrim/) |


## Write-What-Where
[CWE-123](https://cwe.mitre.org/data/definitions/123.html): Write-what-where Condition

> *"Any condition where the attacker has the ability to write an arbitrary value to an arbitrary location, often as the result of a buffer overflow."*

| Author(s) | Source | Article |
| --- | --- | --- |
| Simon Zuckerbraun | Zero Day Initiative | [RCE Without Native Code: Exploitation of a Write-What-Where in Internet Explorer](https://www.thezdi.com/blog/2019/5/21/rce-without-native-code-exploitation-of-a-write-what-where-in-internet-explorer) |
| Taha Karim | Confiant | [Internet Explorer CVE-2019–1367 Exploitation — part 2](https://blog.confiant.com/internet-explorer-cve-2019-1367-exploitation-part-2-8143242b5780) |
| ZecOps Research Team | ZecOps | [Exploiting SMBGhost (CVE-2020-0796) for a Local Privilege Escalation: Writeup + POC](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/) |
