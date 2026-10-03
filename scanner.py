#!/usr/bin/env python3
"""Threaded TCP connect port scanner with live terminal output."""

import argparse
import errno
import html
import json
import queue
import resource
import socket
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

NOTICE = "Scan only systems you own or have written permission to test."

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

# These speak TLS from the first byte, so a plain read only returns handshake noise.
TLS_PORTS = {443, 465, 993, 995, 8443}
# HTTP servers wait for the client to speak first.
HTTP_PORTS = {80, 8000, 8080, 8888}

# Longest table the terminal output will print. Exports are not affected.
MAX_ROWS = 50

STYLES = {"open": "green", "closed": "dim", "filtered": "yellow", "error": "red"}


def parse_ports(text):
    ports = set()
    for part in text.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
        else:
            start = end = int(part)
        if not 1 <= start <= end <= 65535:
            raise ValueError(part)
        ports.update(range(start, end + 1))
    return sorted(ports)


def check_fd_limit(workers):
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return None
    # Every worker holds one socket, and Python needs a few descriptors itself.
    if workers >= soft * 0.8:
        return (f"Warning: {workers} workers is close to the open file limit ({soft}). "
                "Use ./run.sh or lower --workers, otherwise ports may show as 'error'.")
    return None


def grab_banner(sock, port):
    if port in TLS_PORTS:
        return ""
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
    except OSError:
        return ""
    lines = data.decode("utf-8", errors="replace").splitlines()
    if not lines:
        return ""
    banner = lines[0]
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            banner += " | " + line.strip()
    banner = banner.strip()
    # Binary protocols (MySQL, RDP, ...) would only show up as garbage.
    if "\ufffd" in banner or not banner.isprintable():
        return ""
    return banner[:100]


def scan_port(ip, port, timeout, want_banner):
    result = {"port": port, "state": "filtered", "service": SERVICES.get(port, ""), "banner": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        # We ran out of file descriptors. That says nothing about the target,
        # so it must not be reported as filtered.
        result["state"] = "error"
        return result
    try:
        sock.settimeout(timeout)
        code = sock.connect_ex((ip, port))
        if code == 0:
            result["state"] = "open"
            if want_banner:
                result["banner"] = grab_banner(sock, port)
        elif code == errno.ECONNREFUSED:
            result["state"] = "closed"
    except OSError:
        pass
    finally:
        sock.close()
    return result


def scan(ip, ports, args, on_result):
    """Run the scan. on_result is always called from the calling thread."""
    results = []
    done = queue.Queue()
    stop = threading.Event()

    def worker(port):
        if not stop.is_set():
            done.put(scan_port(ip, port, args.timeout, args.banner))

    def collect(result):
        results.append(result)
        on_result(result)

    interrupted = False
    started = time.monotonic()
    pool = ThreadPoolExecutor(max_workers=args.workers)
    try:
        for port in ports:
            pool.submit(worker, port)
        while len(results) < len(ports):
            try:
                collect(done.get(timeout=0.1))
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        interrupted = True
        stop.set()
        # Queued ports are dropped. Ports already in flight finish within one timeout.
        pool.shutdown(wait=True, cancel_futures=True)
        while not done.empty():
            collect(done.get())
    else:
        pool.shutdown()
    results.sort(key=lambda r: r["port"])
    return results, interrupted, time.monotonic() - started


def run_plain(target, ip, ports, args, warning):
    # Results go to stdout, everything else to stderr, so stdout can be piped.
    print(NOTICE, file=sys.stderr)
    if warning:
        print(warning, file=sys.stderr)

    def on_result(r):
        if r["state"] == "open" or args.show_all:
            print(f"{r['port']}\t{r['state']}\t{r['service'] or '-'}\t{r['banner']}", flush=True)

    results, interrupted, duration = scan(ip, ports, args, on_result)
    counts = Counter(r["state"] for r in results)
    summary = (f"{target} ({ip}) ports={args.ports} scanned={len(results)}/{len(ports)} "
               f"open={counts['open']} closed={counts['closed']} filtered={counts['filtered']} "
               f"duration={duration:.2f}s")
    if counts["error"]:
        summary += f" error={counts['error']}"
    if interrupted:
        summary += " interrupted"
    print(summary, file=sys.stderr)
    return results, interrupted, duration


def run_rich(target, ip, ports, args, warning):
    # Imported here so --plain never touches Rich at all.
    from rich.console import Console, Group
    from rich.live import Live
    from rich.markup import escape
    from rich.panel import Panel
    from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                               TextColumn, TimeElapsedColumn)
    from rich.table import Table
    from rich.text import Text

    console = Console()
    console.print(NOTICE, style="bold yellow")
    if warning:
        console.print(warning, style="red")

    progress = Progress(
        TextColumn("Scanning {task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("{task.fields[rate]:.0f} ports/s"),
    )
    task = progress.add_task(ip, total=len(ports), rate=0)
    shown = []
    counts = Counter()
    started = time.monotonic()

    def make_table(rows):
        table = Table()
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("State", no_wrap=True)
        table.add_column("Service", no_wrap=True)
        table.add_column("Banner")
        for r in rows:
            # Text() so that brackets in a banner are not read as Rich markup.
            # Banner is the only column allowed to shrink on a narrow terminal.
            banner = Text(r["banner"], no_wrap=True, overflow="ellipsis")
            table.add_row(str(r["port"]), r["state"], r["service"], banner, style=STYLES[r["state"]])
        return table

    def count_line():
        return "  ".join(f"[{STYLES[s]}]{s} {counts[s]}[/]" for s in ("open", "closed", "filtered"))

    def on_result(r):
        counts[r["state"]] += 1
        if r["state"] == "open" or args.show_all:
            shown.append(r)
        elapsed = max(time.monotonic() - started, 0.001)
        progress.update(task, advance=1, rate=sum(counts.values()) / elapsed)
        # Live cannot scroll, so only show the newest rows that fit on screen.
        # The full sorted table is printed once the scan is over.
        visible = shown[-min(max(console.height - 8, 5), MAX_ROWS):]
        live.update(Group(make_table(visible), count_line(), progress))

    with Live(Group(make_table([]), count_line(), progress), console=console, transient=True) as live:
        results, interrupted, duration = scan(ip, ports, args, on_result)

    if shown:
        # When cutting the table down, drop closed and filtered rows before open ones.
        kept = sorted(shown, key=lambda r: (r["state"] != "open", r["port"]))[:MAX_ROWS]
        console.print(make_table(sorted(kept, key=lambda r: r["port"])))
        if len(shown) > MAX_ROWS:
            console.print(f"{len(shown) - MAX_ROWS} more rows omitted. Use --json or --html for the full list.",
                          style="dim")
    else:
        console.print("No open ports found.")

    lines = [
        f"Target    {escape(target)} ({ip})",
        f"Ports     {args.ports} ({len(ports)} ports)",
        f"Duration  {duration:.2f}s",
        f"Results   {count_line()}",
    ]
    if counts["error"]:
        lines.append(f"[red]Errors    {counts['error']} ports not scanned (out of file descriptors)[/]")
    if interrupted:
        lines.append(f"[red]Interrupted after {len(results)} of {len(ports)} ports[/]")
    console.print(Panel("\n".join(lines), title="Scan summary", expand=False))
    return results, interrupted, duration


def write_html(path, report, show_all):
    rows = ""
    for r in report["results"]:
        if r["state"] == "open" or show_all:
            rows += (f"<tr class='{r['state']}'><td>{r['port']}</td><td>{r['state']}</td>"
                     f"<td>{html.escape(r['service'])}</td><td>{html.escape(r['banner'])}</td></tr>\n")
    counts = report["counts"]
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Port scan of {html.escape(report['target'])}</title>
<style>
body {{ font-family: sans-serif; margin: 2em; }}
table {{ border-collapse: collapse; }}
td, th {{ border: 1px solid #ccc; padding: 4px 12px; text-align: left; }}
.open {{ color: #1a7f37; }}
.closed {{ color: #888; }}
.filtered {{ color: #9a6700; }}
</style>
</head>
<body>
<h1>Port scan of {html.escape(report['target'])} ({report['ip']})</h1>
<p>Ports {html.escape(report['ports'])}, started {report['started']}, took {report['duration']}s.
{'Scan was interrupted.' if report['interrupted'] else ''}</p>
<p>{counts['open']} open, {counts['closed']} closed, {counts['filtered']} filtered</p>
<table>
<tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>
{rows}</table>
</body>
</html>
"""
    with open(path, "w") as f:
        f.write(page)


def main():
    parser = argparse.ArgumentParser(description="TCP connect port scanner. " + NOTICE)
    parser.add_argument("target", help="hostname or IPv4 address")
    parser.add_argument("-p", "--ports", default="1-1024", help="e.g. 80, 1-1024 or 22,80,443 (default 1-1024)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="number of threads (default 100)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="socket timeout in seconds (default 1.0)")
    parser.add_argument("--banner", action="store_true", help="try to read a banner from open ports")
    parser.add_argument("--show-all", action="store_true", help="list closed and filtered ports too")
    parser.add_argument("--plain", action="store_true", help="tab separated output, no colors or live display")
    parser.add_argument("--json", metavar="FILE", help="write results to a JSON file")
    parser.add_argument("--html", metavar="FILE", help="write an HTML report")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        parser.error(f"invalid --ports value: {args.ports}")
    if args.workers < 1 or args.timeout <= 0:
        parser.error("--workers and --timeout must be positive")
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror as e:
        sys.exit(f"Could not resolve {args.target}: {e}")

    started = datetime.now().isoformat(timespec="seconds")
    run = run_plain if args.plain else run_rich
    results, interrupted, duration = run(args.target, ip, ports, args, check_fd_limit(args.workers))

    counts = Counter(r["state"] for r in results)
    report = {
        "target": args.target,
        "ip": ip,
        "ports": args.ports,
        "started": started,
        "duration": round(duration, 2),
        "interrupted": interrupted,
        "counts": {state: counts[state] for state in STYLES if state != "error" or counts[state]},
        "results": results,
    }
    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Wrote {args.json}", file=sys.stderr)
    if args.html:
        write_html(args.html, report, args.show_all)
        print(f"Wrote {args.html}", file=sys.stderr)
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
