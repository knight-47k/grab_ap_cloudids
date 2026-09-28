# grab_ap_cloudids.py

Collects Cloud IDs for unconfigured **CW917x** access points joined to a Catalyst 9800 WLC, and writes them to a CSV.

IMPORTANT: This is personal project and tested by just me. Do not use in production environments without proper review. Cisco or I will not be liable for any damages or issues arising from its use.

## What it does

Stage 1 --> SSH to the WLC, run `show ap summary`, parse the AP table, keep rows where Regulatory Domain is `-UN` and the model starts with `CW917`, then close the WLC session.
Stage 2 --> write `AP Name, IP Address, Cloud ID` to CSV (mode 0600, atomic replace) and print the AP list for review.
Stage 3 --> SSH to each AP in turn, run `show inventory | in CLOUD`, extract the Cloud ID, and rewrite the CSV after every AP so an interrupted run is never lost.

## Requirements

Python 3.9+ (uses `set[...]` / `from __future__ import annotations`) --> `pip install paramiko` --> IP reachability to the WLC management interface and to each AP's management address --> CLI credentials with privilege to run `show ap summary` on the WLC and `show inventory` on the APs.

## Usage

```
python3 grab_ap_cloudids.py --wlc <wlc-host-or-ip> --csv ap_cloudids.csv
python3 grab_ap_cloudids.py --wlc <wlc-host-or-ip> --same-credentials
python3 grab_ap_cloudids.py --wlc <wlc-host-or-ip> --verbose
```

Credentials are prompted interactively; passwords are read with `getpass` and are never echoed, logged, written to disk, or passed as arguments or environment variables. `--same-credentials` reuses the WLC login for the AP sessions.

## Options

`--wlc` (required) --> WLC hostname or IP
`--csv` --> output path, default `ap_cloudids.csv`
`--port` --> SSH port, default 22
`--connect-timeout` --> TCP/SSH connect timeout, default 15s
`--wlc-read-timeout` --> WLC command read timeout, default 60s
`--ap-read-timeout` --> AP command read timeout, default 30s
`--retries` --> attempts per AP, default 2 (auth failures and host-key mismatches are not retried, to avoid account lockout)
`--same-credentials` --> reuse WLC credentials for AP logins
`--strict-host-keys` --> enforce `known_hosts` verification
`--verbose` --> DEBUG logging

## Host key verification

By default host key checking is **skipped**, because AP keys change on reimage or factory reset and a large fleet cannot be pre-seeded into `known_hosts`. Run only on a trusted management network. Use `--strict-host-keys` where your security policy requires verification. A warning is printed whenever verification is disabled.

## Output

CSV with header `AP Name, IP Address, Cloud ID`. APs that fail are left with a blank Cloud ID and reported in the closing summary. Treat the file as sensitive — Cloud IDs are cloud-onboarding claim identifiers, so do not attach it unredacted to a support case or email.

## Exit codes

`0` --> all APs succeeded (or no matching APs found)
`1` --> one or more APs failed, or a fatal CLI error
`2` --> empty username or password at the prompt
`130` --> interrupted with Ctrl-C (sessions closed cleanly)

## Known limitations

The `show ap summary` parser assumes fixed column order and AP names without spaces; IPv6-only APs are not matched. Execution is sequential, so large fleets take time. `show inventory | in CLOUD` requires an AP image that supports output piping.
