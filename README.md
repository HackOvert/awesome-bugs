# awesome-bugs
A collection of software bug types and articles showcasing the hunt for and exploitation of them.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

# Ontologies
* [Common Weakness Enumeration](https://cwe.mitre.org/about/index.html) (CWE)

# Bug Types
* [Type Confusion](#type-confusion)
* [Write-What-Where](#write-what-where)

## Type Confusion
[CWE-843](https://cwe.mitre.org/data/definitions/843.html): Access of Resource Using Incompatible Type ('Type Confusion')

> *"The program allocates or initializes a resource such as a pointer, object, or variable using one type, but it later accesses that resource using a type that is incompatible with the original type."*

| Related Bug | Relationship | Description |
| --- | --- | --- | 
| [CWE-664](https://cwe.mitre.org/data/definitions/664.html) | Grandparent | Improper Control of a Resource Through its Lifetime |
| [CWE-704](https://cwe.mitre.org/data/definitions/704.html) | Parent | Incorrect Type Conversion or Cast |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) | Sibling | Attempt to Access Child of a Non-structure Pointer |
| [CWE-681](https://cwe.mitre.org/data/definitions/681.html) | Sibling | Incorrect Conversion between Numeric Types |

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


## Write-What-Where
[CWE-123](https://cwe.mitre.org/data/definitions/123.html): Write-what-where Condition

> *"Any condition where the attacker has the ability to write an arbitrary value to an arbitrary location, often as the result of a buffer overflow."*

| Related Bug | Relationship | Description |
| --- | --- | --- | 
| [CWE-119](https://cwe.mitre.org/data/definitions/119.html) | Grandparent | Improper Restriction of Operations within the Bounds of a Memory Buffer |
| [CWE-787](https://cwe.mitre.org/data/definitions/787.html) | Parent |Out-of-bounds Write |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Sibling | Double Free |

| Author(s) | Source | Article |
| --- | --- | --- |
| Simon Zuckerbraun | Zero Day Initiative | [RCE Without Native Code: Exploitation of a Write-What-Where in Internet Explorer](https://www.thezdi.com/blog/2019/5/21/rce-without-native-code-exploitation-of-a-write-what-where-in-internet-explorer) |
