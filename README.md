# ReconScan

The purpose of this project is to develop scripts that can be useful in the pentesting workflow, be it for VulnHub VMs, CTFs, hands-on certificates, or real-world targets.

The project currently consists of two major components: a script invoking and aggregating the results of existing tools, and a second script for automated analysis of the aforementioned results from the perspective of exploitability.

In terms of real-world pentesting, these scripts are not meant to replace commercial tools such as Nessus or Nexpose, but they can complement it nicely for finding the latest vulnerabilities and their PoC exploits.

## Network reconnaissance

The `recon.py` script runs various open-source tools in order to enumerate the services on a host. Best run under Kali Linux or similar pentesting-oriented distribution with these tools preinstalled and preconfigured.

The flow followed by the script is as follows:

- Scan all TCP/UDP ports with nmap, service detection, minimal amount of scripts:
	- If there are unidentified services, try amap.
	- For identified software, run vulnerability analysis with `vulnscan.py`
	- For identified services, run further analysis:
		- HTTP(S): nikto, dirb
		- FTP: hydra if requested
		- SMB: enum4linux, samrdump, nbtscan
		- SSH: hydra if requested
		- SNMP: onesixtyone, snmpwalk
		- DNS: attempt zone transfer (axfr) with dig
	- Additionally, all nmap scripts are run for the following services:
	  - HTTP(S), SMTP, POP3, IMAP, FTP, SMB, MSSQL, MySQL, Oracle, SNMP, RDP, VNC

Results will be dumped into the `results/$ip_address` directory, with the `$port_$service_$tool` file naming scheme. The tools are mostly run simultaneously (unless one depends on the result of another) and the CLI output will be aggregated and tagged by the script, so you will see the progress and dirt found by each running script in real-time.

### Origin

This script is inspired by [Mike Czumak's Recon Scan](http://www.securitysift.com/offsec-pwb-oscp/), which he wrote during his OSCP exam. Many modifications can be found on GitHub, however, I wanted to write a script from scratch, familiarizing myself with each tool and their parameterization, instead of just reusing a bunch of scripts found scattered in various repositories, leaving me none the wiser.

### Usage

	usage: recon.py [-h] [-b] [-n] [-p] [-v] [-o OUTPUT] [--nmap NMAP] [--hydra HYDRA]
									address [port] [service]

	Network reconnaissance tool for enumerating the everliving fuck out of a host.

	positional arguments:
		address               address of the host.
		port                  port of the service, if scanning only one port
		service               type of the service, when port is specified

	optional arguments:
		-h, --help            show this help message and exit
		-b, --bruteforce      only bruteforce credentials with hydra
		-n, --dry-run         does not invoke commands
		-p, --parallel        runs multiple commands in parallel, if set
		-v, --verbose         enable verbose output, repeat for more verbosity
		-o OUTPUT, --output OUTPUT
													output directory for the results
		--nmap NMAP           additional nmap arguments
		--hydra HYDRA         additional hydra arguments


#### Example run

	$ ./recon.py -v 192.168.1.84
	[*] Scanning host 192.168.1.84...
	[*] Running task nmap-tcp with nmap -v -sV -sC -T5 -p- -oN "results/192.168.1.84/0_tcp_nmap.txt" -oX "results/192.168.1.84/0_tcp_nmap.xml" 192.168.1.84
	[*] Running task nmap-udp with nmap -v -sV --version-intensity 0 -sC -sU -T5 -oN "results/192.168.1.84/0_udp_nmap.txt" -oX "results/192.168.1.84/0_udp_nmap.xml" 192.168.1.84
	[*] Service 22/tcp is ssh running OpenSSH version 4.7p1 Debian 8ubuntu1.2
	[*] Service 80/tcp is http running Apache httpd version 2.2.8
	[*] Service 137/udp is netbios-ns running Microsoft Windows netbios-ns
	[*] Service 139/tcp is netbios-ssn running Samba smbd version 3.X - 4.X
	[*] Service 445/tcp is netbios-ssn running Samba smbd version 3.0.28a
	[*] Starting scan of services...
	[*] Scanning service ssh on port 22/tcp...
	[*] Scanning service http on port 80/tcp...
	[*] Running task nmap-80 with nmap -vv -sV -T5 -Pn -p 80 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-* -oN "results/192.168.1.84/80_http_nmap.txt" -oX "results/192.168.1.84/80_http_nmap.xml" 192.168.1.84
	[*] Running task curl-1-80 with curl -i http://192.168.1.84:80/ -o "results/192.168.1.84/80_http_index.html"
	[*] Running task curl-2-80 with curl -i http://192.168.1.84:80/robots.txt -o "results/192.168.1.84/80_http_robots.txt"
	[*] Running task dirb-80 with dirb http://192.168.1.84:80 -o "results/192.168.1.84/80_http_dirb.txt" -r
	[*] Running task nikto-80 with nikto -h http://192.168.1.84:80 -o "results/192.168.1.84/80_http_nikto.txt"
	[*] Scanning service netbios-ns on port 137/udp...
	[!] Service netbios-ns has no scanner support.
	[*] Scanning service netbios-ssn on port 139/tcp...
	[*] Running task nmap-139 with nmap -vv -sV -T5 -Pn -p 139 --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-*,smbv2-enabled.nse -oN "results/192.168.1.84/139_smb_nmap.txt" -oX "results/192.168.1.84/139_smb_nmap.xml" 192.168.1.84
	[*] Running task enum4linux-139 with enum4linux -a 192.168.1.84 | tee "results/192.168.1.84/139_smb_enum4linux.txt"
	[*] Running task samrdump-139 with python2 /usr/share/doc/python-impacket/examples/samrdump.py 192.168.1.84 139/SMB | tee "results/192.168.1.84/139_smb_samrdump.txt"
	[*] Scanning service netbios-ssn on port 445/tcp...
	[*] Running task nmap-445 with nmap -vv -sV -T5 -Pn -p 445 --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-*,smbv2-enabled.nse -oN "results/192.168.1.84/445_smb_nmap.txt" -oX "results/192.168.1.84/445_smb_nmap.xml" 192.168.1.84
	[*] Running task enum4linux-445 with enum4linux -a 192.168.1.84 | tee "results/192.168.1.84/445_smb_enum4linux.txt"
	[*] Running task samrdump-445 with python2 /usr/share/doc/python-impacket/examples/samrdump.py 192.168.1.84 445/SMB | tee "results/192.168.1.84/445_smb_samrdump.txt"

## Vulnerability analysis

The `vulnscan.py` script analyses a specified CPE name to determine whether it has any known vulnerabilities and published exploits.

As input, it takes a CPE name, a full name and version, or a path to an xml-based nmap report, which was generated with service detection. When not providing a CPE name, the free-text provided will be fuzzy-matched with the CPE dictionary to check if the provided software name and version has a CPE name. When an nmap report is provided, the CPE names for the identified services are used for the lookup. If the software name and version is available, but the CPE name is not, it will try to fuzzy-match it.

Based on my previous experiences, directly looking up the affected software entries in the CVE database does not always yield the most accurate results, as a software might have multiple CPE names, all referring to the same software. For example, `nginx` might be listed as `cpe:/a:nginx:nginx` or `cpe:/a:igor_sysoev:nginx`, and on the more extreme side, `X11` has 12 CPE aliases. In order to combat this, a CPE alias list is used, which is provided and maintained by the Debian Security team, and all aliases are looked up for a given CPE name. Using this technique tends to generate much better results.

Vulnerabilites are listed and color-coded based on availability:
* gray - no public known exploit,
* yellow - partially public or limited information,
* red - public exploit available.

In order to take it one step further, the ExploitDB and SecurityFocus references are extracted from the CVE entries, which allows the script to provide direct links to the exploits. In order to provide perfect ExploitDB and SecurityFocus results for the vulnerabilities, curated lists will have to be used during database updates. If these lists are missing, ExploitDB and SecurityFocus links will still be displayed, but with issues: the SecurityFocus IDs are listed, but information is not available in the CVE entries themselves on whether the SecurityFocus exploit page has any content or not; similarly, the ExploitDB references seem to be missing quite a few entries.

The curated list for ExploitDB will act as a supplemental EDB-CVE map to the ones found in the CVE references. The SecurityFocus list is a list of SecurityFocus IDs with exploit entries, and this list will be used to determine whether a SecurityFocus CVE reference will be imported or not.

The following exploit databases are currently supported, with provided curated lists:

* **ExploitDB** at `nvd/exploitdb.lst`
* **SecurityFocus** at `nvd/securityfocus.lst`
* **Metasploit** at `nvd/metasploit.lst`
* **1337day** at `nvd/1337day.lst`

### Origin

The idea for this comes from my other open-source project, [Host Scanner](https://github.com/RoliSoft/Host-Scanner), which does exactly this, but is written in C++ and is focused more towards security researchers and system administrators, as opposed to CTF players.

The C++ version has a slightly different feature set compared to this Python version: while the main goal of the Python version is to parse nmap reports and end up at exploit links, the C++ version has its own active and passive network scanner, service identifier, and researcher-oriented features, such as non-intrusive vulnerability validation through package manager changelog reports.

### Usage

	usage: vulnscan.py [-h] [-a] [-e] [-u] [query]
	
	positional arguments:
	  query           CPE name, full name and version to fuzzy match, or path to nmap report (generated with -sV)
	
	optional arguments:
	  -h, --help      show this help message and exit
	  -a, --all       dump all vulnerabilities for a CPE when no version is included (off by default)
	  -e, --exploits  dump only vulnerabilities with public exploits available
	  -u, --update    download the CVE dumps and recreate the local database

#### Example run

	$ ./vulnscan.py 'Apache 2.2.8'
	[*] Performing fuzzy matching for Apache 2.2.8...
	[*] Fuzzy-matched query to name cpe:/a:apache:http_server:2.2.8
	[*] Entry cpe:/a:apache:http_server:2.2.8 has the following vulnerabilities:

	  ** or **

	$ ./vulnscan.py nmap_scan.xml
	[*] Processing nmap report nmap_scan.xml...
	[*] Service 192.168.1.84:80/tcp is cpe:/a:apache:http_server:2.2.8
	[*] Entry cpe:/a:apache:http_server:2.2.8 has the following vulnerabilities:
	>>> CVE-2014-0231 The mod_cgid module in the Apache HTTP Server before 2.4.10 does not have a timeout mechani >
	>>> CVE-2014-0098 The log_cookie function in mod_log_config.c in the mod_log_config module in the Apache HTTP >
	>>> CVE-2013-6438 The dav_xml_get_cdata function in main/util.c in the mod_dav module in the Apache HTTP Serv >
	>>> CVE-2013-2249 mod_session_dbd.c in the mod_session_dbd module in the Apache HTTP Server before 2.4.5 proc >
	>>> CVE-2013-1896 mod_dav.c in the Apache HTTP Server before 2.2.25 does not properly determine whether DAV i >
	>>> CVE-2013-1862 mod_rewrite.c in the mod_rewrite module in the Apache HTTP Server 2.2.x before 2.2.25 write >
	>>> CVE-2012-4558 Multiple cross-site scripting (XSS) vulnerabilities in the balancer_handler function in the >
	>>> CVE-2012-3499 Multiple cross-site scripting (XSS) vulnerabilities in the Apache HTTP Server 2.2.x before  >
	>>> CVE-2012-2687 Multiple cross-site scripting (XSS) vulnerabilities in the make_variant_list function in mo >
	>>> CVE-2012-0883 envvars (aka envvars-std) in the Apache HTTP Server before 2.4.2 places a zero-length direc >
	>>> CVE-2012-0053 protocol.c in the Apache HTTP Server 2.2.x through 2.2.21 does not properly restrict header >
	>>> CVE-2012-0031 scoreboard.c in the Apache HTTP Server 2.2.21 and earlier might allow local users to cause  >
	>>> CVE-2011-4415 The ap_pregsub function in server/util.c in the Apache HTTP Server 2.0.x through 2.0.64 and >
	>>> CVE-2011-4317 The mod_proxy module in the Apache HTTP Server 1.3.x through 1.3.42, 2.0.x through 2.0.64,  >
	>>> CVE-2011-3639 The mod_proxy module in the Apache HTTP Server 2.0.x through 2.0.64 and 2.2.x before 2.2.18 >
	>>> CVE-2011-3607 Integer overflow in the ap_pregsub function in server/util.c in the Apache HTTP Server 2.0. >
	>>> CVE-2011-3368 The mod_proxy module in the Apache HTTP Server 1.3.x through 1.3.42, 2.0.x through 2.0.64,  >
	>>> CVE-2011-3348 The mod_proxy_ajp module in the Apache HTTP Server before 2.2.21, when used with mod_proxy_ >
	>>> CVE-2011-3192 The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x throu >
	>>> CVE-2011-0419 Stack consumption vulnerability in the fnmatch implementation in apr_fnmatch.c in the Apach >
	>>> CVE-2010-1452 The (1) mod_cache and (2) mod_dav modules in the Apache HTTP Server 2.2.x before 2.2.16 all >
	>>> CVE-2010-0434 The ap_read_request function in server/protocol.c in the Apache HTTP Server 2.2.x before 2. >
	>>> CVE-2010-0425 modules/arch/win32/mod_isapi.c in mod_isapi in the Apache HTTP Server 2.0.37 through 2.0.63 >
	>>> CVE-2010-0408 The ap_proxy_ajp_request function in mod_proxy_ajp.c in mod_proxy_ajp in the Apache HTTP Se >
	>>> CVE-2009-3555 The TLS protocol, and the SSL protocol 3.0 and possibly earlier, as used in Microsoft Inter >
	>>> CVE-2009-2699 The Solaris pollset feature in the Event Port backend in poll/unix/port.c in the Apache Por >
	>>> CVE-2009-1891 The mod_deflate module in Apache httpd 2.2.11 and earlier compresses large files until comp >
	>>> CVE-2009-1890 The stream_reqbody_cl function in mod_proxy_http.c in the mod_proxy module in the Apache HT >
	>>> CVE-2009-1195 The Apache HTTP Server 2.2.11 and earlier 2.2 versions does not properly handle Options=Inc >
	>>> CVE-2008-2939 Cross-site scripting (XSS) vulnerability in proxy_ftp.c in the mod_proxy_ftp module in Apac >
	>>> CVE-2008-2364 The ap_proxy_http_process_response function in mod_proxy_http.c in the mod_proxy module in  >
	>>> CVE-2007-6750 The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (da >
	[*] Entry cpe:/a:apache:http_server:2.2.8 has the following public exploits:
	>>> CVE-2014-0231
		- Apache HTTP Server CVE-2014-0231 Remote Denial of Service
		  http://www.securityfocus.com/bid/68742/exploit
	>>> CVE-2014-0098
		- Apache HTTP Server Multiple Denial of Service
		  http://www.securityfocus.com/bid/66303/exploit
	>>> CVE-2013-6438
		- Apache HTTP Server Multiple Denial of Service
		  http://www.securityfocus.com/bid/66303/exploit
	>>> CVE-2013-1862
		- Apache HTTP Server Terminal Escape Sequence in Logs Command Injection
		  http://www.securityfocus.com/bid/59826/exploit
		- RETIRED: Oracle January 2014 Critical Patch Update Multiple
		  http://www.securityfocus.com/bid/64758/exploit
	>>> CVE-2012-4558
		- Apache  HTTP Server Multiple Cross Site Scripting
		  http://www.securityfocus.com/bid/58165/exploit
		- RETIRED: Oracle January 2014 Critical Patch Update Multiple
		  http://www.securityfocus.com/bid/64758/exploit
	>>> CVE-2012-3499
		- Apache  HTTP Server Multiple Cross Site Scripting
		  http://www.securityfocus.com/bid/58165/exploit
		- RETIRED: Oracle January 2014 Critical Patch Update Multiple
		  http://www.securityfocus.com/bid/64758/exploit
	>>> CVE-2012-2687
		- Apache HTTP Server HTML-Injection And Information Disclosure
		  http://www.securityfocus.com/bid/55131/exploit
	>>> CVE-2012-0053
		- Apache - httpOnly Cookie Disclosure
		  https://www.exploit-db.com/exploits/18442
		- Apache HTTP Server 'httpOnly' Cookie Information Disclosure
		  http://www.securityfocus.com/bid/51706/exploit
	>>> CVE-2012-0031
		- Apache HTTP Server Scoreboard Local Security Bypass
		  http://www.securityfocus.com/bid/51407/exploit
	>>> CVE-2011-4317
		- Apache 7.0.x mod_proxy - Reverse Proxy Security Bypass
		  https://www.exploit-db.com/exploits/36352
	>>> CVE-2011-3639
		- Apache 2.2.15 mod_proxy - Reverse Proxy Security Bypass
		  https://www.exploit-db.com/exploits/36663
	>>> CVE-2011-3607
		- Apache HTTP Server 'ap_pregsub()' Function Local Privilege Escalation
		  http://www.securityfocus.com/bid/50494/exploit
	>>> CVE-2011-3368
		- Apache mod_proxy - Reverse Proxy Exposure (PoC)
		  https://www.exploit-db.com/exploits/17969
		- Apache HTTP Server 'mod_proxy' Reverse Proxy Information Disclosure
		  http://www.securityfocus.com/bid/49957/exploit
		- Apache Reverse Proxy Bypass Vulnerability Scanner
		  metasploit auxiliary/scanner/http/rewrite_proxy_bypass
	>>> CVE-2011-3348
		- Apache HTTP Server CVE-2011-3348 Denial Of Service
		  http://www.securityfocus.com/bid/49616/exploit
	>>> CVE-2011-3192
		- Apache - Remote Denial of Service (Memory Exhaustion)
		  https://www.exploit-db.com/exploits/17696
		- Apache - Denial of Service
		  https://www.exploit-db.com/exploits/18221
		- Apache HTTP Server CVE-2011-3192 Denial Of Service
		  http://www.securityfocus.com/bid/49303/exploit
		- Apache Range Header DoS (Apache Killer)
		  metasploit auxiliary/dos/http/apache_range_dos
	>>> CVE-2011-0419
		- Apache 1.4/2.2.x - APR 'apr_fnmatch()' Denial of Service
		  https://www.exploit-db.com/exploits/35738
	>>> CVE-2010-0434
		- Apache 'mod_isapi' Memory Corruption
		  http://www.securityfocus.com/bid/38494/exploit
	>>> CVE-2010-0425
		- Apache 2.2.14 mod_isapi - Dangling Pointer Remote SYSTEM Exploit
		  https://www.exploit-db.com/exploits/11650
		- Win32 - Write-to-file Shellcode (278 bytes)
		  https://www.exploit-db.com/exploits/14288
		- Apache 'mod_isapi' Memory Corruption
		  http://www.securityfocus.com/bid/38494/exploit
		- Apache mod_isapi Dangling Pointer
		  metasploit auxiliary/dos/http/apache_mod_isapi
	>>> CVE-2009-3555
		- TLS - Renegotiation (PoC)
		  https://www.exploit-db.com/exploits/10579
		- Mozilla NSS - NULL Character CA SSL Certificate Validation Security Bypass
		  https://www.exploit-db.com/exploits/10071
		- Multiple Vendor TLS Protocol Session Renegotiation Security
		  http://www.securityfocus.com/bid/36935/exploit
	>>> CVE-2009-1195
		- Apache 'Options' and 'AllowOverride' Directives Security Bypass
		  http://www.securityfocus.com/bid/35115/exploit
	>>> CVE-2008-2939
		- Apache 'mod_proxy_ftp' Wildcard Characters Cross-Site Scripting
		  http://www.securityfocus.com/bid/30560/exploit

## Licensing

Copyright (c) `2017` `RoliSoft <root@rolisoft.net>`

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed in the hope that it will be useful, but without any warranty; without even the implied warranty of merchantability or fitness for a particular purpose.

For more information regarding the terms and conditions of this software, please read the full legal text of the GNU General Public License version 3, a copy of which is available in the [LICENSE.md](LICENSE.md) file. Otherwise, see &lt;<http://www.gnu.org/licenses/>&gt;.

Some of the invoked tools are licensed under GPL or a form of GPL-derived license with added clauses further restricting how data produced by the tool can be processed, e.g. nmap.