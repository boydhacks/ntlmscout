```
          __  __                                __
   ____  / /_/ /___ ___  ______________  __  __/ /_
  / __ \/ __/ / __ `__ \/ ___/ ___/ __ \/ / / / __/
 / / / / /_/ / / / / / (__  ) /__/ /_/ / /_/ / /_
/_/ /_/\__/_/_/ /_/ /_/____/\___/\____/\__,_/\__/

   hunting exposed NTLM
   BoydHacks  ·  github.com/BoydHacks
```

# ntlmscout

**One tool to squeeze every drop of information out of internet-exposed NTLM endpoints.**

An unauthenticated NTLM negotiation leaks a surprising amount of internal Active Directory detail before a single credential is ever sent. `ntlmscout` sends an NTLM Type-1 (NEGOTIATE) message across a wide range of transports, fully decodes the Type-2 (CHALLENGE) that comes back, and pulls out everything: internal NetBIOS/DNS host and domain names, the AD forest, the OS build (mapped to a friendly Windows version), the server clock (and skew), negotiate flags, and every AV_PAIR — then enriches it with adjacent unauthenticated disclosures and an optional, lockout-safe password spray.

Pure standard library. Single file. Python 3.7+. No dependencies.

## Features

- **Every transport in one tool** — HTTP(S) (with endpoint discovery), SMB2/3, MSSQL/TDS, SMTP, IMAP, POP3, NNTP, LDAP(S), and RDP/CredSSP(NLA).
- **Deep Type-2 decode** — NetBIOS + DNS host/domain, forest/tree name, OS build → friendly name (client vs. server disambiguated), server timestamp + clock skew, SPN, MachineID, channel bindings, and full negotiate-flag breakdown.
- **Interprets, not just dumps** — honest **member vs. Domain Controller** classification (a DC is only claimed when a DC service actually answers), and a security-posture read (SMB/LDAP signing, EPA/channel-binding, NTLMv1/LM weak crypto).
- **Recovers the internal IP** — the one thing NTLM itself can't give you — via IIS Host-header disclosure (CVE-2000-0649), WebDAV PROPFIND, RPC `IOXIDResolver::ServerAlive2` (TCP 135), and TLS/RDP certificate IP SANs.
- **Extra disclosures** — TLS/RDP certificate CN + SANs, Exchange `X-FEServer`/`X-CalculatedBETarget` header leaks, and anonymous **LDAP rootDSE** enrichment (naming contexts, `dnsHostName`, AD functional levels).
- **No wordlist false positives** — random "canary" paths detect hosts that challenge *every* path (site-wide IIS Windows Auth, or an ADC / reverse proxy in front of the app) and collapse the wordlist noise to a single, honest finding. If every canary is dropped by a slow or throttling host the guard falls back on the wordlist hit ratio rather than failing open, and the report says which signal decided it.
- **Fast** — a port-liveness gate skips every probe on a closed port, so filtered hosts don't cost you a wall of timeouts.
- **Lockout-safe spray mode** — password-spray ordering (one password across all users per round), NTLM Type-3 or HTTP Basic against the most effective endpoint, with a clear valid / invalid / inconclusive verdict.
- **Report-ready output** — grouped per-host summary plus JSON, NDJSON, CSV, and a NetExec-style hosts file. Output files are written with owner-only permissions.

## Install

```bash
git clone https://github.com/BoydHacks/ntlmscout
cd ntlmscout
python3 ntlmscout.py --help
```

No `pip install`, no virtualenv — it only uses the Python standard library.

## Tests

```bash
python3 -m unittest test_ntlmscout
```

## Usage

```bash
# recon a single IP or host (full sweep of every NTLM-capable port)
python3 ntlmscout.py 203.0.113.10
python3 ntlmscout.py mail.example.com

# a specific endpoint, or a whole range, or a target list
python3 ntlmscout.py https://mail.example.com/ews/
python3 ntlmscout.py 10.0.0.0/24
python3 ntlmscout.py -I targets.txt --json results.json

# route everything through Burp / a CONNECT proxy
python3 ntlmscout.py -I targets.txt --proxy 127.0.0.1:8080

# lockout-safe password spray against the best endpoint
python3 ntlmscout.py --spray -I hosts.txt -u users.txt -p 'Winter2026!' --delay 1800
```

Recon is a **full sweep by default**. Trim it with `--no-discover` (skip the HTTP path wordlist) or `--no-internal-ip` (skip the cert/OXID/IIS checks). See `--help` for the full menu.

### Scan cost

A full sweep is not cheap per host, so the size of a range matters more than it
looks. One bare host fans out to **376 probes** by default: 23 NTLM-capable
ports, 6 of them web ports multiplied by the 83-entry HTTP path wordlist, plus
the internal-disclosure checks and the catch-all canaries per web endpoint. The
scope flags change that sharply.

| Flags | Probes per host | A /24 | A /16 |
|---|---|---|---|
| default | 376 | 95,504 | 24,640,784 |
| `--no-discover` | 40 | 10,160 | 2,621,360 |
| `--no-discover --no-internal-ip` | 23 | 5,842 | 1,507,282 |

Closed ports are pruned with one fast connect per `host:port` before any probe
runs, so the live probe count on a real network is usually far lower. The
planner streams in batches and never holds the whole plan in memory, so peak
memory tracks `--threads`, not the size of the range.

A **probe budget** guards against a run that would take days by accident:
ntlmscout refuses to start if the plan exceeds `--max-jobs` probes (500,000 by
default) and tells you which flag to reach for. Raise it deliberately with
`--max-jobs N`, or `--max-jobs 0` for no limit. Note that results for every
probe are held in memory until the scan ends, so a very large `--max-jobs` still
costs memory over a long run; prefer splitting the range.

## Example output

```
========================================================================
  HOST: 203.0.113.10   (EXCH01.corp.example.com)
------------------------------------------------------------------------
  External address  : 203.0.113.10
  Internal address  : 10.0.0.25
  Realm             : CORP
  Realm type        : domain
  NetBIOS host      : EXCH01
  NetBIOS domain    : CORP
  DNS host          : EXCH01.corp.example.com
  DNS domain        : corp.example.com
  DNS forest        : corp.example.com
  OS                : Windows Server 2019
  OS build          : 10.0.17763
  Server time (UTC) : 2026-01-01 12:00:00
  Time skew (s)     : -0.1
  Role              : Domain member
  NTLM endpoints identified: 4
      - https://203.0.113.10/ews/
      - https://203.0.113.10/rpc/
      - https://203.0.113.10/autodiscover/
      - smb://203.0.113.10:445
========================================================================

[+] 4 exposed NTLM endpoint(s) on 1 of 1 host(s).
```

The discovered endpoints are listed on-screen automatically. Add `-o log.txt`
for a full per-field log, or `--json`/`--csv` for machine-readable output.

## Spray safety

Spray mode is opt-in and hardwired to **password-spray ordering** — one password is tried across every account per round, so no account ever sees more than one attempt per round. Set `--delay` to the target's lockout observation window and confirm the lockout policy before running. It reports valid, cleanly-rejected, and inconclusive results separately so a negative result is trustworthy rather than an artifact of a broken oracle.

## Credits & acknowledgements

`ntlmscout` stands on the shoulders of the researchers and tools that pioneered NTLM endpoint reconnaissance. Their ideas, techniques, and endpoint wordlists directly informed this project:

- **NTLMRecon** — [pwnfoo / Sachin Kamath](https://github.com/pwnfoo/NTLMRecon) (Python) and [Praetorian](https://github.com/praetorian-inc/NTLMRecon) (Go): HTTP endpoint discovery and challenge decoding, and the [blog](https://www.praetorian.com/blog/automating-the-discovery-of-ntlm-authentication-endpoints/) that framed the approach. Their path wordlists were a starting point for the merged list here.
- **ntlmscan** — [nyxgeek (TrustedSec)](https://github.com/nyxgeek/ntlmscan): OWA / Lync / ADFS / Autodiscover path enumeration, and [lyncsmash](https://github.com/nyxgeek/lyncsmash) for the Skype-for-Business paths.
- **ntlm_challenger** — [nopfor](https://github.com/nopfor/ntlm_challenger): the clean HTTP + SMB challenge-decoding reference this tool's parser was modeled after.
- **nmap `*-ntlm-info` NSE scripts** — Justin Cacak (http/imap/pop3/smtp/nntp/telnet/ms-sql) and Tom Sellers (rdp): the per-protocol recipes for coaxing a Type-2 out of each service.
- **NetExec / CrackMapExec** — the [NetExec team](https://github.com/Pennyw0rth/NetExec) and byt3bl33d3r: host-fingerprint banners and the hosts-file / role-detection approach.
- **Impacket** — [Fortra/SecureAuth](https://github.com/fortra/impacket) and **pyspnego** — [@jborean93](https://github.com/jborean93/pyspnego): reference implementations for NTLMSSP/SPNEGO decoding.
- **MailSniper** — [@dafthack (Beau Bullock)](https://github.com/dafthack/MailSniper): the OWA domain-harvest and spray lineage that shaped this tool's spray design.
- **The Hacker Recipes** and the wider AD community: documentation of the `IOXIDResolver::ServerAlive2` internal-address technique and NTLM relay/posture concepts.

Protocol details follow Microsoft's **[MS-NLMP]** Open Specification and Eric Glass's classic [davenport NTLM notes](http://davenport.sourceforge.net/ntlm.html). The IIS internal-IP disclosure is **CVE-2000-0649**.

If your work belongs here and I've missed you, open an issue — credit is due and I'll add it.

## Author

**BoydHacks** — [github.com/BoydHacks](https://github.com/BoydHacks)
