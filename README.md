## CVE-2016-5673: Ultr@VNC Repeater ##
=============

This repository contains the POCs for CVE-2016-5673. This vulnerability was published at our talk at DEFCON 24 in 2016: https://www.defcon.org/html/defcon-24/dc-24-speakers.html#Klijnsma

### Timeline: ###

- Vulnerability discovered: `February 13th 2016`
- Vulnerability reported: `April 21st 2016`
- Vulnerability fixed in version `1.30` released around `June 30th 2016`

### The vulnerability ###

Ultr@VNC Repeaters are basically raw TCP proxies which purpose is to tunnel VNC sessions to machines in internal networks exposed via these repeaters. These repeaters do not inspect the actual traffic that passes through them. With limited to no default filtering anyone from the outside can connect to any internal host on any port. This means from the outside access to the internal network is possible.
