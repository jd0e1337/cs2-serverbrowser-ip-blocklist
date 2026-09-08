# cs2-serverbrowser-ip-blocklist
Public IPv4 blocklists from [CS2monitor](https://www.cs2monitor.com/blocklist).

- [blocklist.txt](blocklist.txt): Abuse and Unclassified addresses.
- [blocklist-with-restricted.txt](blocklist-with-restricted.txt): the same list plus League / Restricted addresses.

Each file contains one IPv4 address or CIDR network per line. Direct address rules, automatically matched IPs, and IPs extracted from individual server rules are included and deduplicated. Blocking an exported IP affects every port and any other services sharing that IP. Restricted does not mean abuse; Unclassified does not mean confirmed abuse. Recorded historical matches do not establish current ownership or behavior.

The CS2monitor live server checks its local public API every 15 minutes, at minutes 7, 22, 37 and 52. It publishes to this repository using a dedicated SSH deploy key. A commit is created only when addresses change. Failed, incomplete, malformed or empty downloads leave the published lists unchanged. Both files are built from the same response.

The exporter runs as a separate systemd service on the live server. GitHub Actions does not run a second sync. Publishing these files does not automatically update anyone's Windows Firewall.
