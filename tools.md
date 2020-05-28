---
layout: page
title: Tools
permalink: /tools/
---

# NoPowerShell
_PowerShell rebuilt in C# for Red Teaming purposes_

**Url:** [https://github.com/bitsadmin/nopowershell/](https://github.com/bitsadmin/nopowershell/)

NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No `System.Management.Automation.dll` is used; only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: `rundll32 NoPowerShell.dll,main` in restricted environments.

![NoPowerShell DLL](https://raw.githubusercontent.com/bitsadmin/nopowershell/master/Pictures/NoPowerShellDll.png "NoPowerShell DLL")


# WES-NG
_Windows Exploit Suggester - Next Generation_

**Url:** [https://github.com/bitsadmin/wesng/](https://github.com/bitsadmin/wesng/)

WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported.

![Windows Exploit Suggester - Next Generation](https://raw.githubusercontent.com/bitsadmin/wesng/master/demo.gif "Windows Exploit Suggester - Next Generation")


# FakeLogonScreen
_Fake Windows logon screen to steal passwords_

**Url:** [https://github.com/bitsadmin/fakelogonscreen/](https://github.com/bitsadmin/fakelogonscreen/)

FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user's password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk.

![FakeLogonScreen](https://raw.githubusercontent.com/bitsadmin/fakelogonscreen/master/demo.gif "FakeLogonScreen")


# Other projects
View the above projects and more on the [bitsadmin GitHub](https://github.com/bitsadmin?tab=repositories).
