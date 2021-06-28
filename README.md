# TP Link TL-WR841N router cybersecurity analysis

Table of Contents
=================
* [TP Link TL-WR841N router cybersecurity analysis](#TP-Link-TL-WR841N-router-cybersecurity-analysis)
* [Prerequisite](#Prerequisite)
* [Plan of Analysis](#Plan-of-Analysis)
* [Technical Information](#Technical-Information)
	* [Open Ports](#Open-Ports)
	* [TCP Port Scan](#TCP-Port-Scan)
	* [UDP Port Scan](#UDP-Port-Scan)
	* [OS Detection](#OS-Detection)
* [Known exploits](#Known-exploits)
* [Further work](#Further-work)

# Prerequisite

After testing the security of my IP camera I've decided to do an overview of the security of my router.

# Plan of Analysis

1. Gathering of technical information about the router.
2. Find firmware and installed software.
3. Check for known exploits.
4. Check the severity of found exploits.
5. Present the ways of how to mitigate the risks.
6. Conclusion.

# Technical Information

In this section I will present the technical information that I have gathered about tested router. It includes finding open TCP and UDP ports and detect the OS and it's version running within the router.

## Open Ports

In this subsection I am presenting the results of a port scan.

### TCP Port Scan

First TCP port scan results which are presented further.

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     Dropbear sshd 2012.55 (protocol 2.0)
| ssh-hostkey:
|   1024 2d:20:4b:ed:24:f6:13:5d:32:af:44:88:35:5b:04:de (DSA)
|_  1040 df:61:f7:f5:bc:aa:e6:9a:2d:6a:20:cc:98:38:68:38 (RSA)
80/tcp    open  http    TP-LINK WR841N WAP http config
|_http-title: TL-WR841N
1900/tcp  open  upnp    ipOS upnpd (TP-LINK TL-WR841N WAP 11.0; UPnP 1.0)
49152/tcp open  http    Huawei HG8245T modem http config
|_http-title: Site doesn't have a title.
```

Nmap scan found ***4*** TCP ports - `22`, `80`, `1900` and `49152`. Some details about each port are presented below:
1. Port `22` is a standart `ssh` port and for this service ***Dropbear sshd 2012.55*** software is used. Also a couple of ssh hostkeys were discovered.
2. Port `80` is a standard `http` port and this service is controlled by ***TP-LINK WR841N WAP http config*** software.
3. Port `1900` is used for `upnp` or universal plug and play service and ***ipOS upnpd*** software is used for controlling it.
4. Port `49152` is an alternate http service run by ***Huawei HG8245T modem http config*** and it looks like a different built-in module within the router for some kind of http services.

### UDP Port Scan

In this section UDP port scan results are presented.

```
PORT     STATE         SERVICE VERSION
53/udp   open          domain  ISC BIND 9.10.3-P4 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Debian
|_dns-recursion: Recursion appears to be enabled
67/udp   open|filtered dhcps
1900/udp open|filtered upnp
```

Nmap scan found ***3*** open UDP ports - `53`, `67` and `1900`. Some details about each port are presented below:
1. Port `53` has a `domain` service run by ***ISC BIND 9.10.3-P4*** software and it is used for some DNS related stuff. Also ***DNS recursion*** seems to be enabled. Further reading needs to be done to fully understand what it is used for and what potential risks of this service are.
2. Port `67` is used for `dhcps` or ***Dynamic Host Configuration Protocol*** service and could be used for automatic IP network configuration.
3. Port `1900` is used for `upnp` service. Same as it's TCP counterpart.

## OS Detection

In this section the results of OS detection scan are presented.

```
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS deta Linux 2.6.17 - 2.6.36
```

The router is recognized as a `general purpose` device and is running a `Linux 2.6` operating system with likely version ranging from `2.6.17` to `2.6.36`.

# Known exploits
In this section I will gather information about known exploits, published in ***Common Vulnerabilities and Exposures (CVE)*** lists. For finding this information I plan to use [cve.mitre.org](https://cve.mitre.org/cve/) and [National Vulnerability Database (NVD)](https://nvd.nist.gov/vuln) webpages. First I will check for publicly disclosed vulnerabilities found within the software detected during port scan of the router.

1. Dropbear sshd 2012.55:
	* ***[CVE-2013-4421](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4421)*** - The buf_decompress function in packet.c in Dropbear SSH Server before 2013.59 allows remote attackers to cause a denial of service (memory consumption) via a compressed packet that has a large size when it is decompressed.
	* ***[CVE-2013-4434](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4434)*** - Dropbear SSH Server before 2013.59 generates error messages for a failed logon attempt with different time delays depending on whether the user account exists, which allows remote attackers to discover valid usernames.
	* ***CVE-2016-3116*** - CRLF injection vulnerability in Dropbear SSH before 2016.72 allows remote authenticated users to bypass intended shell-command restrictions via crafted X11 forwarding data.
	* ***CVE-2016-7406*** - Format string vulnerability in Dropbear SSH before 2016.74 allows remote attackers to execute arbitrary code via format string specifiers in the (1) username or (2) host argument.
	* ***CVE-2016-7407*** - The dropbearconvert command in Dropbear SSH before 2016.74 allows attackers to execute arbitrary code via a crafted OpenSSH key file.
	* ***CVE-2016-7408*** - The dbclient in Dropbear SSH before 2016.74 allows remote attackers to execute arbitrary code via a crafted (1) -m or (2) -c argument.
	* ***CVE-2016-7409*** - The dbclient and server in Dropbear SSH before 2016.74, when compiled with DEBUG_TRACE, allows local users to read process memory via the -v argument, related to a failed remote ident.
	* ***CVE-2017-9079*** - Dropbear before 2017.75 might allow local users to read certain files as root, if the file has the authorized_keys file format with a command= option. This occurs because ~/.ssh/authorized_keys is read with root privileges and symlinks are followed.
	* ***CVE-2018-15599*** - The recv_msg_userauth_request function in svr-auth.c in Dropbear through 2018.76 is prone to a user enumeration vulnerability because username validity affects how fields in SSH_MSG_USERAUTH messages are handled, a similar issue to CVE-2018-15473 in an unrelated codebase.
2. ISC BIND 9.10.3-P4:
	* ***CVE-2016-2775*** - ISC BIND 9.x before 9.9.9-P2, 9.10.x before 9.10.4-P2, and 9.11.x before 9.11.0b2, when lwresd or the named lwres option is enabled, allows remote attackers to cause a denial of service (daemon crash) via a long request that uses the lightweight resolver protocol.
	* ***CVE-2016-2776*** - buffer.c in named in ISC BIND 9 before 9.9.9-P3, 9.10.x before 9.10.4-P3, and 9.11.x before 9.11.0rc3 does not properly construct responses, which allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a crafted query.
	* ***CVE-2016-6170*** - ISC BIND through 9.9.9-P1, 9.10.x through 9.10.4-P1, and 9.11.x through 9.11.0b1 allows primary DNS servers to cause a denial of service (secondary DNS server crash) via a large AXFR response, and possibly allows IXFR servers to cause a denial of service (IXFR client crash) via a large IXFR response and allows remote authenticated users to cause a denial of service (primary DNS server crash) via a large UPDATE message.
	* ***CVE-2016-8864*** - named in ISC BIND 9.x before 9.9.9-P4, 9.10.x before 9.10.4-P4, and 9.11.x before 9.11.0-P1 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a DNAME record in the answer section of a response to a recursive query, related to db.c and resolver.c.
	* ***CVE-2016-9131*** - named in ISC BIND 9.x before 9.9.9-P5, 9.10.x before 9.10.4-P5, and 9.11.x before 9.11.0-P2 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a malformed response to an RTYPE ANY query.
	* ***CVE-2016-9147*** - named in ISC BIND 9.9.9-P4, 9.9.9-S6, 9.10.4-P4, and 9.11.0-P1 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a response containing an inconsistency among the DNSSEC-related RRsets.
	* ***CVE-2016-9444*** - named in ISC BIND 9.x before 9.9.9-P5, 9.10.x before 9.10.4-P5, and 9.11.x before 9.11.0-P2 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a crafted DS resource record in an answer.
	* ***CVE-2021-25214*** - In BIND 9.8.5 -> 9.8.8, 9.9.3 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 -> 9.16.13-S1 of BIND 9 Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND 9.17 development branch, when a vulnerable version of named receives a malformed IXFR triggering the flaw described above, the named process will terminate due to a failed assertion the next time the transferred secondary zone is refreshed.
	* ***CVE-2021-25215*** - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 -> 9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND 9.17 development branch, when a vulnerable version of named receives a query for a record triggering the flaw described above, the named process will terminate due to a failed assertion check. The vulnerability affects all currently maintained BIND 9 branches (9.11, 9.11-S, 9.16, 9.16-S, 9.17) as well as all other versions of BIND 9.
	* ***CVE-2021-25216*** - In BIND 9.5.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.11.3-S1 -> 9.11.29-S1 and 9.16.8-S1 -> 9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.1 of the BIND 9.17 development branch, BIND servers are vulnerable if they are running an affected version and are configured to use GSS-TSIG features. In a configuration which uses BIND's default settings the vulnerable code path is not exposed, but a server can be rendered vulnerable by explicitly setting values for the tkey-gssapi-keytab or tkey-gssapi-credential configuration options. Although the default configuration is not vulnerable, GSS-TSIG is frequently used in networks where BIND is integrated with Samba, as well as in mixed-server environments that combine BIND servers with Active Directory domain controllers. For servers that meet these conditions, the ISC SPNEGO implementation is vulnerable to various attacks, depending on the CPU architecture for which BIND was built: For named binaries compiled for 64-bit platforms, this flaw can be used to trigger a buffer over-read, leading to a server crash. For named binaries compiled for 32-bit platforms, this flaw can be used to trigger a server crash due to a buffer overflow and possibly also to achieve remote code execution. We have determined that standard SPNEGO implementations are available in the MIT and Heimdal Kerberos libraries, which support a broad range of operating systems, rendering the ISC implementation unnecessary and obsolete. Therefore, to reduce the attack surface for BIND users, we will be removing the ISC SPNEGO implementation in the April releases of BIND 9.11 and 9.16 (it had already been dropped from BIND 9.17). We would not normally remove something from a stable ESV (Extended Support Version) of BIND, but since system libraries can replace the ISC SPNEGO implementation, we have made an exception in this case for reasons of stability and security.
3. TP-LINK WR841N:
	* ***CVE-2017-9466*** - The executable httpd on the TP-Link WR841N V8 router before `TL-WR841N(UN)_V8_170210` contained a design flaw in the use of DES for block encryption. This resulted in incorrect access control, which allowed attackers to gain read-write access to system settings through the protected router configuration service tddp via the LAN and Ath0 (Wi-Fi) interfaces.
	* ***CVE-2018-12574*** - CSRF exists for all actions in the web interface on TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n devices.
	* ***CVE-2018-12575*** - On TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 171019 Rel.55346n devices, all actions in the web interface are affected by bypass of authentication via an HTTP request.
	* ***CVE-2018-12576*** - TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n devices allow clickjacking.
	* ***CVE-2018-12577*** - The Ping and Traceroute features on TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n devices allow authenticated blind Command Injection.
	* ***CVE-2019-17147*** - This vulnerability allows remote attackers to execute arbitrary code on affected installations of TP-LINK TL-WR841N routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the web service, which listens on TCP port 80 by default. When parsing the Host request header, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length static buffer. An attacker can leverage this vulnerability to execute code in the context of the admin user. Was ZDI-CAN-8457.
	* ***CVE-2020-35575*** - A password-disclosure issue in the web interface on certain TP-Link devices allows a remote attacker to get full administrative access to the web panel. This affects WA901ND devices before 3.16.9(201211) beta, and Archer C5, Archer C7, MR3420, MR6400, WA701ND, WA801ND, WDR3500, WDR3600, WE843N, WR1043ND, WR1045ND, WR740N, WR741ND, WR749N, WR802N, WR840N, WR841HP, WR841N, WR842N, WR842ND, WR845N, WR940N, WR941HP, WR945N, WR949N, and WRD4300 devices.
	* ***CVE-2020-35576*** - A Command Injection issue in the traceroute feature on TP-Link TL-WR841N V13 (JP) with firmware versions prior to 201216 allows authenticated users to execute arbitrary code as root via shell metacharacters, a different vulnerability than CVE-2018-12577.
	* ***CVE-2020-8423*** - A buffer overflow in the httpd daemon on TP-Link TL-WR841N V10 (firmware version 3.16.9) devices allows an authenticated remote attacker to execute arbitrary code via a GET request to the page for the configuration of the Wi-Fi network.

# Further work

Further I plan to do the following:

1. Try to exploit found vulnerabilities and see what damage I could do.
2. Install `OpenWRT` as a firmware of the router.
