Table of Contents
=================
* [TP Link TL-WR841N router cybersecurity analysis](#TP-Link-TL-WR841N-router-cybersecurity-analysis)
* [Prerequisite](Prerequisite)
* [Plan of Analysis](Plan-of-Analysis)
* [Technical Information](Technical-Information)
	* [Open Ports](Open Ports)
	* [TCP Port Scan](TCP-Port-Scan)
	* [UDP Port Scan](UDP-Port-Scan)
	* [OS Detection](OS-Detection)
* [Known exploits](#Known-exploits)

# TP Link TL-WR841N router cybersecurity analysis

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
In this section I will gather information about known exploits, published in ***Common Vulnerabilities and Exposures (CVE)*** lists. For this purpose I plan to use [cve.mitre.org](https://cve.mitre.org/cve/) webpage.
