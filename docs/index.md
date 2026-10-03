---
title: port-scanner
---

# port-scanner

A small TCP connect port scanner for the command line, written in Python by
Dhruv Choudhary.

**Scan only systems you own or have written permission to test.**

## Demo

<link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/asciinema-player@3.17.0/dist/bundle/asciinema-player.css" />
<div id="demo-player"></div>
<script src="https://cdn.jsdelivr.net/npm/asciinema-player@3.17.0/dist/bundle/asciinema-player.min.js"></script>
<script>
  AsciinemaPlayer.create(
    'https://asciinema.org/a/GneSzREVczsYDRnB.cast',
    document.getElementById('demo-player'),
    { autoPlay: true, loop: true, controls: true }
  );
</script>

If the player does not load, watch the recording
[on asciinema.org](https://asciinema.org/a/GneSzREVczsYDRnB).

## What it does

- Scans TCP ports with a full connect scan, 1-1024 by default
- Reports each port as open, closed or filtered
- Uses a thread pool (100 workers by default) so a scan takes seconds
- Optionally grabs banners from open ports, for example the SSH version string
- Shows a live table and progress bar in the terminal
- Has a plain output mode for scripts, plus JSON and HTML export

## Quick start

```
git clone https://github.com/RYzZzEN007/port-scanner.git
cd port-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./run.sh 192.168.1.10 -p 22,80,443 --banner
```

## Example

A scan of a small range on the local machine, where a Python `http.server` is
listening on port 8000:

```
$ ./run.sh 127.0.0.1 --ports 7990-8010 --banner
Scan only systems you own or have written permission to test.
┏━━━━━━┳━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ State ┃ Service ┃ Banner                                                ┃
┡━━━━━━╇━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 8000 │ open  │         │ HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 Python/3.9.6 │
└──────┴───────┴─────────┴───────────────────────────────────────────────────────┘
╭───────────── Scan summary ──────────────╮
│ Target    127.0.0.1 (127.0.0.1)         │
│ Ports     7990-8010 (21 ports)          │
│ Duration  0.01s                         │
│ Results   open 1  closed 20  filtered 0 │
╰─────────────────────────────────────────╯
```

A scan of a remote host. `scanme.nmap.org` is the host that Nmap's maintainers
provide for exactly this purpose, and they explicitly permit test scans
against it. `--show-all` is used here so the closed port is listed too:

```
$ ./run.sh scanme.nmap.org --ports 22,80,135,445,3389 --banner --show-all
Scan only systems you own or have written permission to test.
┏━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ State  ┃ Service ┃ Banner                                          ┃
┡━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   22 │ open   │ ssh     │ SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13      │
│   80 │ open   │ http    │ HTTP/1.0 200 OK | Server: Apache/2.4.7 (Ubuntu) │
│  135 │ open   │ msrpc   │                                                 │
│  445 │ open   │ smb     │                                                 │
│ 3389 │ closed │ rdp     │                                                 │
└──────┴────────┴─────────┴─────────────────────────────────────────────────┘
╭────────────── Scan summary ──────────────╮
│ Target    scanme.nmap.org (45.33.32.156) │
│ Ports     22,80,135,445,3389 (5 ports)   │
│ Duration  1.01s                          │
│ Results   open 4  closed 1  filtered 0   │
╰──────────────────────────────────────────╯
```

Ports 22 and 80 returned real banners. Ports 135 and 445 are reported open
but returned nothing, and the same ports show as filtered when this host is
scanned from a different network. They are most likely being answered by a
device on the network path and not by the target. See the limitations section
of [How it works](how-it-works.md) for why a connect scan cannot tell the difference.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `-p`, `--ports` | `1-1024` | `80`, `1-1024`, `22,80,443` or a mix |
| `-w`, `--workers` | `100` | Number of threads |
| `-t`, `--timeout` | `1.0` | Socket timeout in seconds |
| `--banner` | off | Read a banner from each open port |
| `--show-all` | off | List closed and filtered ports too (table capped at 50 rows) |
| `--plain` | off | Tab separated output for scripts |
| `--json FILE` | | Write results as JSON |
| `--html FILE` | | Write an HTML report |

## Read more

- [How it works](how-it-works.md): the TCP handshake, the three port states,
  and the scanner's limitations
- [README](https://github.com/RYzZzEN007/port-scanner#readme): installation and usage in more detail
- [DECISIONS.md](https://github.com/RYzZzEN007/port-scanner/blob/main/DECISIONS.md): the design choices and the
  alternatives considered
