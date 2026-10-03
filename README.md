# port-scanner

A small TCP connect port scanner for the command line, written in Python. It
scans a range of ports with a thread pool, tells open, closed and filtered
ports apart, can grab service banners, and shows progress live in the terminal
using [Rich](https://github.com/Textualize/rich).

**Scan only systems you own or have written permission to test.** Port
scanning someone else's machine without permission can be illegal and will
often get your IP address blocked.

## Demo

A recorded terminal session of the scanner running:
<https://asciinema.org/a/GneSzREVczsYDRnB>

## Install

Needs Python 3.10 or newer (developed on 3.13, macOS). The only dependency is
Rich.

```
git clone https://github.com/RYzZzEN007/port-scanner.git
cd port-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
./run.sh <target> [options]
```

`run.sh` raises the open file limit to 4096 (`ulimit -n 4096`), activates the
venv and runs `scanner.py`. macOS only allows 256 open files per process by
default, which is not much room for a scanner that opens one socket per
thread. You can also run `python scanner.py` directly. The scanner checks the
limit on startup and warns if the worker count is close to it.

| Option | Default | Meaning |
| --- | --- | --- |
| `-p`, `--ports` | `1-1024` | Ports to scan: `80`, `1-1024`, `22,80,443`, or a mix like `22,80,8000-8100` |
| `-w`, `--workers` | `100` | Number of threads |
| `-t`, `--timeout` | `1.0` | Socket timeout in seconds |
| `--banner` | off | Try to read a banner from each open port |
| `--show-all` | off | List closed and filtered ports too, not only open ones. The terminal table stops at 50 rows; exports keep everything |
| `--plain` | off | Tab separated output with no Rich, for scripts |
| `--json FILE` | | Write full results to a JSON file |
| `--html FILE` | | Write an HTML report |

Examples:

```
./run.sh 192.168.1.10
./run.sh 192.168.1.10 -p 22,80,443 --banner
./run.sh myserver.local -p 1-65535 -w 500 -t 0.5
./run.sh 192.168.1.10 --plain | cut -f1
./run.sh 192.168.1.10 --json scan.json --html scan.html
```

Press Ctrl-C to stop a scan early. Ports that have not started yet are
dropped, and the results collected so far are still printed and exported.

## Example output

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
of [docs/how-it-works.md](docs/how-it-works.md) for why a connect scan cannot tell the difference.

While the scan is running, the table fills in as ports are found and a
progress bar underneath shows ports done, elapsed time and ports per second.
Open ports are green, closed ports dim and filtered ports yellow.

The remaining examples were run against a few test listeners on `127.0.0.1`.
With `--plain`, results go to stdout as `port<TAB>state<TAB>service<TAB>banner`
in the order they finish. The notice and the summary line go to stderr, so
stdout can be piped straight into other tools.

```
$ ./run.sh 127.0.0.1 -p 2120-2122,2222,8080,8443 --banner --plain --show-all
Scan only systems you own or have written permission to test.
2120	closed	-	
2122	closed	-	
8443	open	https-alt	
2121	open	-	220 (vsFTPd 3.0.5)
2222	open	-	SSH-2.0-OpenSSH_9.6
8080	open	http-alt	HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 Python/3.13.16
127.0.0.1 (127.0.0.1) ports=2120-2122,2222,8080,8443 scanned=6/6 open=4 closed=2 filtered=0 duration=0.00s
```

The JSON export always contains every scanned port, including closed and
filtered ones:

```json
{
  "target": "127.0.0.1",
  "ip": "127.0.0.1",
  "ports": "2120-2122,2222,8080,8443",
  "started": "2026-10-03T18:09:51",
  "duration": 0.0,
  "interrupted": false,
  "counts": { "open": 4, "closed": 2, "filtered": 0 },
  "results": [
    { "port": 2120, "state": "closed", "service": "", "banner": "" },
    { "port": 2121, "state": "open", "service": "", "banner": "220 (vsFTPd 3.0.5)" }
  ]
}
```

(`results` is shortened here.)

## Port states

| State | Meaning | How it is detected |
| --- | --- | --- |
| open | Something is listening | `connect_ex` returns 0 |
| closed | Host is up, nothing is listening | `connect_ex` returns `ECONNREFUSED` |
| filtered | No usable answer, usually a firewall | Timeout or any other error |

If the scanner itself runs out of file descriptors, the affected ports are
counted as `error` instead of being guessed. This only happens when the
startup warning was ignored.

## Service names

Service names come from a hardcoded dict of about 25 common ports in
`scanner.py`. Python does have `socket.getservbyport`, but it reads the
system's services database (`/etc/services`), which differs between operating
systems and may be missing in minimal containers. The same scan would then
print different names on different machines, so the scanner uses its own
table. A service name is only a guess based on the port number. It does not
prove what is actually running there.

## More documentation

- [docs/how-it-works.md](docs/how-it-works.md): what a TCP connect scan does
  and what the scanner cannot do
- [DECISIONS.md](DECISIONS.md): design choices and the alternatives considered

The `docs/` folder is also a GitHub Pages site. To publish it, go to the
repository's Settings, then Pages, and choose "Deploy from a branch" with the
`main` branch and the `/docs` folder.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Dhruv Choudhary.
