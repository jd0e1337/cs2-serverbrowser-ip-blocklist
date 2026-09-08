# cs2-serverbrowser-ip-blocklist
Public IPv4 blocklists from [CS2monitor](https://www.cs2monitor.com/blocklist).

- [blocklist.txt](blocklist.txt): Abuse and Unclassified addresses.
- [blocklist-with-restricted.txt](blocklist-with-restricted.txt): the same list plus League / Restricted addresses.

Each file contains one IPv4 address or CIDR network per line. Direct address rules, automatically matched IPs, and IPs extracted from individual server rules are included and deduplicated. Blocking an exported IP affects every port and any other services sharing that IP. Restricted does not mean abuse; Unclassified does not mean confirmed abuse. Recorded historical matches do not establish current ownership or behavior.

GitHub Actions checks the [public API](https://www.cs2monitor.com/api/blocklist) every 15 minutes, at minutes 7, 22, 37 and 52. Scheduled runs can be delayed by GitHub. A commit is created only when addresses change; request timestamps do not cause commits. Failed, incomplete, malformed or empty downloads leave the published lists unchanged. Both files are built from the same response.

The workflow can also be run manually under **Actions → Sync public blocklists → Run workflow**. It uses this repository's `GITHUB_TOKEN` with `contents: write`; branch rules must allow its pushes to `main`. No credentials for CS2monitor are required. Publishing these files does not automatically update anyone's Windows Firewall.

Run `node --test scripts/sync-blocklist.test.mjs` to test the exporter, or `node scripts/sync-blocklist.mjs` to refresh both files locally (Node.js 22 or newer).
