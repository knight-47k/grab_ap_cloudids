#!/usr/bin/env python3
"""
grab_ap_cloudids.py

IMPORTANT: This is personal project and tested by just me. Do not use in production environments without proper review. Cisco or I will not be liable for any damages or issues arising from its use.

Workflow:
  WLC SSH --> 'show ap summary' --> filter RD == '-UN' and AP Model startswith 'CW917'
          --> CSV (AP Name, IP Address, Cloud ID) --> close WLC session
          --> per-AP SSH --> 'show inventory | in CLOUD' --> fill Cloud ID --> rewrite CSV

Security notes:
  * SSH host key verification is SKIPPED by default, because a large AP fleet cannot
    realistically be pre-seeded into known_hosts and AP keys change on reimage.
    Run on a trusted management network. Use --strict-host-keys to enforce
    known_hosts verification instead.

Usage:
  python3 grab_ap_cloudids.py --wlc 10.107.70.10 --csv ap_cloudids.csv
  python3 grab_ap_cloudids.py --wlc 10.107.70.10 --same-credentials
  python3 grab_ap_cloudids.py --wlc 10.107.70.10 --strict-host-keys

Requires: pip install paramiko
"""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import logging
import os
import re
import socket
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

try:
    import paramiko
except ImportError:  # pragma: no cover
    sys.exit("ERROR: paramiko is required --> pip install paramiko")


LOG = logging.getLogger("cloudid")

CSV_HEADER = ["AP Name", "IP Address", "Cloud ID"]
TARGET_RD = "-UN"
TARGET_MODEL_PREFIX = "CW917"

MAC = r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

# Scans the whole buffer rather than line-by-line, so records that share a physical
# line (wrapped output) or are split by pagination artefacts are still matched.
AP_RECORD_RE = re.compile(
    rf"(?P<name>\S+)\s+"
    rf"(?P<slots>\d+)\s+"
    rf"(?P<model>\S+)\s+"
    rf"(?P<eth>{MAC})\s+"
    rf"(?P<radio>{MAC})\s+"
    rf"(?P<cc>[A-Z]{{2,3}})\s+"
    rf"(?P<rd>-\S+)\s+"
    rf"(?P<ip>{IPV4})\s+"
    rf"(?P<state>\S+)"
)

CLOUDID_RE = re.compile(r"CLOUDID\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9\-]{4,})")
PROMPT_RE = re.compile(r"(?:^|[\r\n])[^\r\n]{1,80}?[#>]\s?$")
MORE_RE = re.compile(r"--\s*More\s*--|<---\s*More\s*--->", re.IGNORECASE)
PRESS_RETURN_RE = re.compile(r"Press RETURN to get started", re.IGNORECASE)


class CliError(RuntimeError):
    """Any recoverable failure while talking to a device."""


class NoVerifyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept any host key without prompting or persisting it to known_hosts."""

    def missing_host_key(self, client, hostname, key) -> None:
        LOG.debug(
            "host key not verified for %s (%s %s)",
            hostname, key.get_name(), key.get_fingerprint().hex()
        )


@dataclass(frozen=True)
class ApRecord:
    name: str
    model: str
    rd: str
    ip: str


class Secret:
    """Password container: redacted repr, best-effort zeroisation."""

    __slots__ = ("_buf",)

    def __init__(self, value: str) -> None:
        self._buf = bytearray(value.encode("utf-8"))

    def reveal(self) -> str:
        return self._buf.decode("utf-8")

    def clear(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        del self._buf[:]

    def __repr__(self) -> str:  # never leak into logs or tracebacks
        return "<Secret redacted>"

    __str__ = __repr__


class CliSession:
    """Interactive SSH shell with hard timeouts and guaranteed teardown."""

    def __init__(
        self,
        host: str,
        username: str,
        secret: Secret,
        *,
        label: str,
        port: int = 22,
        connect_timeout: float = 15.0,
        read_timeout: float = 30.0,
        strict_host_keys: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self._secret = secret
        self.label = label
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.strict_host_keys = strict_host_keys
        self._client: Optional[paramiko.SSHClient] = None
        self._chan: Optional[paramiko.Channel] = None

    # -- context management -------------------------------------------------
    def __enter__(self) -> "CliSession":
        self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def open(self) -> None:
        LOG.info("[%s] SSH connect --> %s:%s as %s",
                 self.label, self.host, self.port, self.username)
        client = paramiko.SSHClient()
        if self.strict_host_keys:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # known_hosts is deliberately NOT loaded: this also tolerates keys that
            # CHANGED (AP reimaged / factory reset), which AutoAddPolicy would reject.
            client.set_missing_host_key_policy(NoVerifyPolicy())

        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self._secret.reveal(),
                look_for_keys=False,
                allow_agent=False,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
            )
        except paramiko.AuthenticationException as exc:
            client.close()
            raise CliError(f"authentication rejected ({exc})") from exc
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise CliError(f"host key mismatch ({exc})") from exc
        except paramiko.SSHException as exc:
            client.close()
            raise CliError(f"SSH negotiation failed ({exc})") from exc
        except socket.timeout as exc:
            client.close()
            raise CliError("TCP/SSH connect timed out") from exc
        except OSError as exc:
            client.close()
            raise CliError(f"network unreachable/refused ({exc})") from exc

        self._client = client
        try:
            chan = client.invoke_shell(width=512, height=1000)
            chan.settimeout(self.read_timeout)
            self._chan = chan
            self._read_until_prompt(first_login=True)
            self._disable_paging()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._chan is not None:
            try:
                if self._chan.send_ready():
                    self._chan.send("exit\n")
                    time.sleep(0.3)
            except Exception:
                pass
            try:
                self._chan.close()
            except Exception:
                pass
            self._chan = None
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            LOG.info("[%s] SSH session closed cleanly", self.label)

    # -- primitives ---------------------------------------------------------
    def _disable_paging(self) -> None:
        for cmd in ("terminal length 0", "terminal width 512"):
            try:
                self.run(cmd, read_timeout=10.0)
            except CliError:
                LOG.debug("[%s] '%s' not accepted, relying on --More-- handling",
                          self.label, cmd)

    def _read_until_prompt(
        self, *, read_timeout: Optional[float] = None, first_login: bool = False
    ) -> str:
        assert self._chan is not None
        timeout = read_timeout if read_timeout is not None else self.read_timeout
        deadline = time.monotonic() + timeout
        buf: List[str] = []
        idle_start = time.monotonic()

        while True:
            if time.monotonic() > deadline:
                raise CliError(f"timed out after {timeout:.0f}s waiting for CLI prompt")
            if self._chan.closed:
                raise CliError("remote closed the channel unexpectedly")
            if self._chan.recv_ready():
                try:
                    chunk = self._chan.recv(65535).decode("utf-8", errors="replace")
                except socket.timeout as exc:
                    raise CliError("read timed out") from exc
                if not chunk:
                    raise CliError("remote closed the stream")
                buf.append(chunk)
                idle_start = time.monotonic()
                text = "".join(buf)
                if MORE_RE.search(text[-80:]):           # never hang on pagination
                    self._chan.send(" ")
                    continue
                if first_login and PRESS_RETURN_RE.search(text[-200:]):
                    self._chan.send("\n")
                    continue
                if PROMPT_RE.search(text[-200:]):
                    return text
            else:
                if time.monotonic() - idle_start > timeout:
                    raise CliError("no output received (stalled session)")
                time.sleep(0.15)

    def run(self, command: str, *, read_timeout: Optional[float] = None) -> str:
        if self._chan is None:
            raise CliError("session is not open")
        LOG.info("[%s] running --> %s", self.label, command)
        try:
            self._chan.send(command + "\n")
        except (OSError, paramiko.SSHException) as exc:
            raise CliError(f"unable to send command '{command}' ({exc})") from exc
        raw = self._read_until_prompt(read_timeout=read_timeout)
        return self._clean(raw, command)

    @staticmethod
    def _clean(raw: str, command: str) -> str:
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if lines and command.strip() in lines[0]:
            lines = lines[1:]
        if lines and PROMPT_RE.search("\n" + lines[-1]):
            lines = lines[:-1]
        return MORE_RE.sub("", "\n".join(lines))


# -- parsing / CSV ---------------------------------------------------------
def parse_ap_summary(output: str) -> List[ApRecord]:
    records: List[ApRecord] = []
    seen: set[Tuple[str, str]] = set()
    for m in AP_RECORD_RE.finditer(output):
        ip = m.group("ip")
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        key = (m.group("name"), ip)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            ApRecord(name=m.group("name"), model=m.group("model"),
                     rd=m.group("rd"), ip=ip)
        )
    return records


def select_unconfigured(records: Iterable[ApRecord]) -> List[ApRecord]:
    hits: List[ApRecord] = []
    for rec in records:
        if rec.rd.upper() != TARGET_RD:
            continue
        if not rec.model.upper().startswith(TARGET_MODEL_PREFIX):
            LOG.warning("%s has RD %s but model %s does not match %s* --> skipped",
                        rec.name, rec.rd, rec.model, TARGET_MODEL_PREFIX)
            continue
        hits.append(rec)
    return hits


def write_csv(path: str, rows: List[List[str]]) -> None:
    """Atomic write --> temp file in the same directory, then os.replace."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".cloudid-", suffix=".csv")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(CSV_HEADER)
            writer.writerows(rows)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_csv(path: str) -> List[List[str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    if not rows or rows[0] != CSV_HEADER:
        raise CliError(f"{path} does not have the expected header {CSV_HEADER}")
    return [r + [""] * (3 - len(r)) for r in rows[1:] if any(c.strip() for c in r)]


# -- stages ----------------------------------------------------------------
def collect_from_wlc(args, username: str, secret: Secret) -> List[ApRecord]:
    print("\n== Stage 1/3 : WLC inventory ==")
    with CliSession(
        args.wlc, username, secret,
        label=f"WLC {args.wlc}",
        port=args.port,
        connect_timeout=args.connect_timeout,
        read_timeout=args.wlc_read_timeout,
        strict_host_keys=args.strict_host_keys,
    ) as wlc:
        output = wlc.run("show ap summary", read_timeout=args.wlc_read_timeout)

    records = parse_ap_summary(output)
    if not records:
        raise CliError("no AP rows parsed from 'show ap summary' --> "
                       "check privileges/output format")
    LOG.info("Parsed %d AP record(s) from the WLC", len(records))
    return records


def fetch_cloud_id(row_name: str, ip: str, username: str, secret: Secret, args) -> str:
    last_error = "unknown error"
    for attempt in range(1, args.retries + 1):
        session = CliSession(
            ip, username, secret,
            label=f"AP {row_name} ({ip})",
            port=args.port,
            connect_timeout=args.connect_timeout,
            read_timeout=args.ap_read_timeout,
            strict_host_keys=args.strict_host_keys,
        )
        try:
            session.open()
            out = session.run("show inventory | in CLOUD",
                              read_timeout=args.ap_read_timeout)
            m = CLOUDID_RE.search(out)
            if not m:
                raise CliError("command ran but no CLOUDID line returned")
            cloud_id = m.group(1)
            LOG.info("[AP %s (%s)] Cloud ID --> %s", row_name, ip, cloud_id)
            return cloud_id
        except CliError as exc:
            last_error = str(exc)
            LOG.error("[AP %s (%s)] attempt %d/%d failed --> %s",
                      row_name, ip, attempt, args.retries, last_error)
            if "authentication rejected" in last_error or "host key mismatch" in last_error:
                break   # do not retry and risk an account lockout
            time.sleep(min(2.0 * attempt, 5.0))
        finally:
            session.close()
    raise CliError(last_error)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Collect Cloud IDs for -UN CW917x APs from a Catalyst 9800 WLC."
    )
    p.add_argument("--wlc", required=True, help="WLC hostname or IP")
    p.add_argument("--csv", default="ap_cloudids.csv",
                   help="output CSV path (default: ap_cloudids.csv)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--connect-timeout", type=float, default=15.0)
    p.add_argument("--wlc-read-timeout", type=float, default=60.0)
    p.add_argument("--ap-read-timeout", type=float, default=30.0)
    p.add_argument("--retries", type=int, default=2,
                   help="attempts per AP (default 2)")
    p.add_argument("--same-credentials", action="store_true",
                   help="reuse the WLC credentials for the AP logins")
    p.add_argument("--strict-host-keys", action="store_true", default=False,
                   help="require SSH host keys to be present in known_hosts "
                        "(default: host key verification is skipped)")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    if not args.strict_host_keys:
        LOG.warning("SSH host key verification is DISABLED --> use only on a trusted "
                    "management network (--strict-host-keys to enforce)")

    wlc_secret: Optional[Secret] = None
    ap_secret: Optional[Secret] = None
    try:
        wlc_user = input(f"WLC username for {args.wlc}: ").strip()
        if not wlc_user:
            print("Username cannot be empty.")
            return 2
        pw = getpass.getpass("WLC password (not echoed): ")
        if not pw:
            print("Password cannot be empty.")
            return 2
        wlc_secret = Secret(pw)
        del pw

        records = collect_from_wlc(args, wlc_user, wlc_secret)
        targets = select_unconfigured(records)

        rows = [[r.name, r.ip, ""] for r in targets]
        write_csv(args.csv, rows)
        print(f"\nCSV created --> {args.csv} ({len(rows)} row(s), mode 0600)")

        if not rows:
            print("No CW917x APs with RD '-UN' found --> nothing further to do.")
            return 0

        print("\n== Stage 2/3 : APs requiring Cloud ID ==")
        print(f"APs identified with RD '{TARGET_RD}' and model "
              f"{TARGET_MODEL_PREFIX}*: {len(rows)}")
        for name, ip, _ in rows:
            print(f"  {name} --> {ip}")

        if args.same_credentials:
            ap_user = wlc_user
            ap_secret = Secret(wlc_secret.reveal())
            print("\nReusing WLC credentials for AP logins.")
        else:
            ap_user = input("\nAP username: ").strip()
            if not ap_user:
                print("AP username cannot be empty.")
                return 2
            appw = getpass.getpass("AP password (not echoed): ")
            if not appw:
                print("AP password cannot be empty.")
                return 2
            ap_secret = Secret(appw)
            del appw

        print("\n== Stage 3/3 : Harvesting Cloud IDs ==")
        rows = read_csv(args.csv)
        ok = failed = 0
        for idx, row in enumerate(rows, start=1):
            name, ip = row[0], row[1]
            print(f"[{idx}/{len(rows)}] SSH to {name} ({ip}) --> "
                  f"pulling 'show inventory | in CLOUD'")
            try:
                row[2] = fetch_cloud_id(name, ip, ap_user, ap_secret, args)
                ok += 1
            except CliError as exc:
                row[2] = ""
                print(f"        FAILED --> {exc} (Cloud ID left blank)")
                failed += 1
            write_csv(args.csv, rows)   # checkpoint after every AP
        print(f"\nSummary --> success {ok} | failed {failed} | CSV {args.csv}")
        return 0 if failed == 0 else 1

    except KeyboardInterrupt:
        print("\nInterrupted by user --> sessions closed.")
        return 130
    except CliError as exc:
        LOG.error("Fatal --> %s", exc)
        return 1
    finally:
        for s in (wlc_secret, ap_secret):
            if s is not None:
                s.clear()


if __name__ == "__main__":
    sys.exit(main())