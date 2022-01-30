# TP Link TL-WR841N router cybersecurity analysis

Cyber security analysis of TP Link TL-WR841N router.
Github Pages version of this analysis can be found by [following this link](https://kostasereksonas.github.io/tp-link-tl-wr841n-security-analysis/)

Table of Contents
=================
* [TP Link TL-WR841N router cybersecurity analysis](#TP-Link-TL-WR841N-router-cybersecurity-analysis)
* [Plan of Analysis](#Plan-of-Analysis)
* [Technical Information](#Technical-Information)
	* [Open Ports](#Open-Ports)
	* [TCP Port Scan](#TCP-Port-Scan)
	* [UDP Port Scan](#UDP-Port-Scan)
	* [OS Detection](#OS-Detection)
* [Written Exploits](#Written-Exploits)
	* [Authentication Bypass Exploit](#Authentication-Bypass-Exploit)
	* [Command Injection Exploit](#Command-Injection-Exploit)
* [Further Work](#Further-Work)

# Plan of Analysis

The plan of TP Link TL-WR841N router cybersecurity analysis is as follows:

1. Gather of technical and network information about the router.
2. Intercept and analyze network traffic of the router.
3. Find firmware and a list of software installed within the router.
4. Check CVE lists for published known exploits found within the router's software and check their severity score.
5. Investigate found exploits and try a practical exploitation of these vulnerabilities on a given TP Link TL-WR841N router (i.e. found or custom made scripts for exploiting a certain vulnerability) for getting a better understanding of potential risks that found vulnerabilities pose.
6. Research the possible ways of mitigation for the given the risks.
7. Give conclusions of the analysis.
8. Research the possibility of using `OpenWRT` as the router's firmware.

# Technical Information

In this section I will present the technical and network information that I have gathered about tested TP Link TP-WR841N router. This section includes information about:
	1. Finding open TCP ports.
	2. Finding open UDP ports.
	3. Detection of the Operating System (OS) within the TP Link TL-WR841M router.
	4. Detection of the version of the OS that is running within the TP Link TL-WR841M router.

## Open Ports

In this subsection of Technical information gathering section I am presenting the results of a ***port scan*** that I have done on the tested router. For all the further scans `nmap` tool was used.

### TCP Port Scan

As mentioned before, for finding open TCP ports and services that are running on top of them, `nmap` tool was used. The command for this specific scan was `nmap -v -sS -sV -sC -p- X.X.X.X`, where `X.X.X.X` is IP address of the TP Link router. Short description of every used flag is presented below:

```
-v		Verbosity. Gives more information about what the scan is doing.
-sS		Stealth scan. Fast, accurate and non-intrusive test of a selected target.
-sV		Version scan. Used to detect versions of services running on specific open ports of IP Camera.
-sC		Scripts scan. Uses a default set of most common `nmap` scripts.
-p-		Check all 65535 TCP ports for if they are open.
```

Results of this scan are presented below:

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

Nmap scan found ***4*** TCP ports whose numbers are `22`, `80`, `1900` and `49152`. Some details about each port are presented below:
1. Port `22` is a standart port for `ssh` service and on top of this port ***Dropbear sshd 2012.55*** service is running. Also a couple of ssh hostkeys were discovered.
2. Port `80` is a standard `http` port and is controlled by ***TP-LINK WR841N WAP http config*** software.
3. Port `1900` is an `upnp` or ***universal plug and play*** port and is controlled by ***ipOS upnpd*** service.
4. Port `49152` is a port for ***alternate http service*** and is controlled by ***Huawei HG8245T modem http config*** service. It looks like a different built-in module within the router for connecting to some kind of http services.

### UDP Port Scan

After finding TCP ports I have conducted a search for ***UDP*** ports. Same `nmap` tool was used, although this time `-sU` flag for ***UDP scan*** was used insead of TCP stealth scan (-sS). The full command for this scan was `nmap -v -sU -sV X.X.X.X`, where `X.X.X.X` is IP address for the TP Link router. Results for this scan are presented below:

```
PORT     STATE         SERVICE VERSION
53/udp   open          domain  ISC BIND 9.10.3-P4 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Debian
|_dns-recursion: Recursion appears to be enabled
67/udp   open|filtered dhcps
1900/udp open|filtered upnp
```

Nmap scan found ***3*** open UDP ports with numbers `53`, `67` and `1900`. Some details about each port are presented below:
1. Port `53` has a `domain` service controlled by ***ISC BIND 9.10.3-P4*** and it is used for some DNS related stuff. Also ***DNS recursion*** seems to be enabled. Further reading needs to be done to fully understand what it is used for and what could potential risks of this service be.
2. Port `67` is controlled by `dhcps` or ***Dynamic Host Configuration Protocol*** service and could be used for automatic IP network configuration.
3. Port `1900` is used for `upnp` or ***universal plug and play*** service, same as it's TCP counterpart.

## OS Detection

To determine type and version of the OS installed within the TP Link router, `nmap` tool with `-O` flag was used. The full command was `nmap -v -sS -sV -O X.X.X.X`, where X.X.X.X is an IP address of TP Link router. The results of this scan are presented below:

```
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS deta Linux 2.6.17 - 2.6.36
```

The router is recognized as a `general purpose` device and it is running a `Linux 2.6` operating system with likely version ranging from `2.6.17` to `2.6.36`.

# Written Exploits

In this section I will present an in-depth analysis of couple exploits for TP LINK TL-WR841N router that I have found in [exploit-db page](https://www.exploit-db.com/). These exploits are:
1. [Authenticaton Bypass Exploit](https://www.exploit-db.com/exploits/44781).
2. [Command Injection Exploit](https://www.exploit-db.com/exploits/50058).

I will start with ***Authentication Bypass Exploit*** and later go to analyze ***Command Injection Exploit***.

## Authentication Bypass Exploit

This exploit, found on [Exploit-db](https://www.exploit-db.com/exploits/44781) was written by BlackFog team at [SecureLayer7.net](https://www.SecureLayer7.net/). If the Referer Header is set as `http://192.168.0.1/mainFrame.htm`, then no authentication is needed for following commands. Although, this exploit did not work for my router.

![Failed Auth Bypass](/images/Failed_Auth_Bypass.png)

## Command Injection Exploit

For now I have tried to run the Python script found in the Exploit-db link but it did not work.

![Failed Injection](/images/Failed_Injection.png)

# Code analysis

In this section I will analyze the [Index page source code](/scripts/login.js) and [linked encryption file](/scripts/encrypt.js) javascript code files.

# Further Work

Further I plan to do the following:

1. Search for pre-made exploits of TP Link TL WR841N router.
2. Try to practically exploit found vulnerabilities and see what potential damage could be done.
3. Present potential fixes and mitigations of exploited vulnerabilities.
4. Research the possibility of using `OpenWRT` as a firmware of the router.
