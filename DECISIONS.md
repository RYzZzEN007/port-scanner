# Design decisions

Each entry lists what was decided, what else was considered, and why this
option won.

## 1. `connect_ex` instead of `connect`

**Decision:** Use `socket.connect_ex`, which returns an error number instead
of raising an exception.

**Alternatives:** `socket.connect` inside `try/except`, catching
`ConnectionRefusedError`, `TimeoutError` and `OSError` separately.

**Why:** The scanner's whole job is to turn the result of a connection attempt
into one of three states, and `connect_ex` gives that result as a plain
integer: `0` is open, `errno.ECONNREFUSED` is closed, anything else is
filtered. With `connect`, a refused connection is an exception, and on a
normal scan most ports are refused, so the common case would go through
exception handling a thousand times. The `if/elif` on the return code is also
easier to read than three `except` blocks. There is still one `except OSError`
around the call, because `connect_ex` can raise for problems that are not
connection results, and those are treated as filtered.

## 2. Threads instead of asyncio

**Decision:** `concurrent.futures.ThreadPoolExecutor` with blocking sockets.

**Alternatives:** `asyncio` with `asyncio.open_connection` and a semaphore;
`multiprocessing`; non-blocking sockets with `selectors`.

**Why:** A port scan is almost entirely waiting on the network. Blocking
socket calls release the GIL while they wait, so threads give real concurrency
here. Asyncio would scale to more simultaneous connections with less memory,
but the limit that matters in practice is the number of file descriptors, not
thread overhead (see entry 3), and a few hundred threads are cheap. Blocking
code is also simpler: `scan_port` reads top to bottom as "connect, check the
code, maybe read a banner", and the banner code can use plain `recv` with the
socket timeout. `multiprocessing` adds process startup and pickling costs for
no benefit on I/O work. `selectors` would mean writing an event loop by hand.

## 3. Pool size and the file descriptor limit

**Decision:** Default to 100 workers. At startup, read the soft limit with
`resource.getrlimit(resource.RLIMIT_NOFILE)` and print a warning if the worker
count is at 80% of it or more. Ship `run.sh`, which runs `ulimit -n 4096`
before starting the scanner.

**Alternatives:** Silently cap the worker count to fit the limit; raise the
limit from inside Python with `resource.setrlimit`; ignore the limit and let
`socket()` fail.

**Why:** Each worker holds one open socket, and every socket is a file
descriptor. macOS sets `ulimit -n` to 256 by default, and Python already uses
some descriptors for stdin, stdout, stderr and imported files. 100 workers fit
comfortably under 256, so the default works even without `run.sh`. Asking for
300 workers under a 256 limit makes `socket()` fail with "Too many open
files". `run.sh` raises the limit to 4096 so larger pools work.

A warning was chosen over a silent cap because the user asked for a specific
number and should know it is not safe, not have it changed behind their back.
`setrlimit` from inside Python was skipped because it can fail depending on
the hard limit, and a shell `ulimit` is the usual, visible way to do it.

If the limit is hit anyway, the affected ports are reported with a separate
`error` state. Marking them filtered would be a wrong statement about the
target when the real problem is local.

## 4. Timeout default of 1.0 seconds

**Decision:** `--timeout` defaults to 1.0 seconds.

**Alternatives:** 0.5 seconds (faster), 3 seconds or more (safer on bad
links), an adaptive timeout based on measured round trip time.

**Why:** Open and closed ports answer in one round trip, which is a few
milliseconds on a LAN and normally well under 300 ms over the internet. Only
filtered ports use the full timeout, so the timeout decides how long a
firewalled scan takes: 1024 filtered ports with 100 workers and a 1 second
timeout take roughly 10 seconds. At 3 seconds that becomes half a minute. At
0.5 seconds a slow or lossy link starts reporting real ports as filtered. One
second leaves a lot of margin over normal latency while keeping the worst case
short. An adaptive timeout is what nmap does, but it is a lot of extra logic
for a tool this size, and the flag lets the user tune it by hand.

## 5. Queue instead of a lock for Rich thread safety

**Decision:** Worker threads never touch Rich. Each worker puts its result on
a `queue.Queue`. The main thread reads the queue and is the only thread that
updates the table, the counters and the progress bar.

**Alternatives:** Let workers update the table directly while holding a
`threading.Lock`; use `as_completed` on the futures.

**Why:** Rich's `Live` display is not thread safe to modify from many threads.
A lock would work only if every single access to the table, the counters and
the progress bar remembered to take it, and one forgotten spot would produce a
garbled display that is hard to reproduce. With a queue there is nothing to
forget, because the workers have no reference to the display at all. They only
do network work.

The queue also made two other things simple. The plain output mode uses the
same `scan` function with a different callback, and Ctrl-C handling lives in
one place, the main loop, which is where Python delivers `KeyboardInterrupt`
anyway. `as_completed` would also keep updates on the main thread, but the
loop with `queue.get(timeout=0.1)` wakes up regularly, which keeps Ctrl-C
responsive.

One detail: `Live` runs its own background thread that redraws the screen a
few times a second. That thread belongs to Rich and takes Rich's own lock. It
is not one of the scanner's worker threads.

## 6. No SYN scan

**Decision:** Only a full TCP connect scan is implemented.

**Alternatives:** A SYN ("half-open") scan that sends a SYN, reads the reply
and never completes the handshake, built with raw sockets or scapy.

**Why:** A SYN scan needs raw sockets to build TCP packets by hand, and raw
sockets need root. A tool that must be run with `sudo` is harder to use
safely and harder to trust. It would also need packet building, checksums and
a way to capture replies, which behaves differently on macOS, Linux and
Windows. That is most of what nmap already does well. A connect scan uses the
normal `connect()` system call, works for any user on any OS, and gives the
same open, closed and filtered answers. The cost is that it completes the
handshake, so it is slower per port and shows up in the target's logs.

## 7. Hardcoded service names instead of `socket.getservbyport`

**Decision:** A dict of about 25 common ports in `scanner.py`.

**Alternatives:** `socket.getservbyport(port)`, or shipping nmap's
`nmap-services` file.

**Why:** `getservbyport` reads the system services database, which is
different on macOS, Linux distributions and Windows, and can be nearly empty
in containers. The same scan would label ports differently depending on where
it runs. A small dict gives the same output everywhere and covers the ports
people actually look for. The full nmap list would be more complete but adds a
data file and a licence to think about.

## 8. Banner grabbing: push, pull and TLS ports

**Decision:** With `--banner`, the scanner reuses the socket that was just
connected. On HTTP ports (80, 8000, 8080, 8888) it sends
`HEAD / HTTP/1.0\r\n\r\n` and then reads. On TLS ports (443, 465, 993, 995,
8443) it skips the banner. On every other port it just reads. A reply that is
not printable text is dropped.

**Alternatives:** Send the HTTP request to every port; wrap TLS ports with the
`ssl` module and read the certificate; read first and send a probe only if
nothing arrives.

**Why:** SSH, FTP and SMTP servers speak first, so reading is enough, and
sending an HTTP request to them would be wrong and noisy. HTTP servers wait
for the client, so reading without sending would just time out. TLS ports
answer a plain read with nothing, or with handshake bytes, which is the binary
noise the banner column should not contain. Doing a real TLS handshake is a
reasonable feature but it is a different kind of probe and was left out to
keep the scope small. `HEAD` and HTTP/1.0 were chosen because the reply is
only headers and the server closes the connection afterwards. The choice is
made by port number, so a web server on an unusual port gets no banner.

## 9. Only open ports are listed by default

**Decision:** The table, the plain output and the HTML report list open ports
only. `--show-all` adds closed and filtered ports. The table printed in the
terminal is capped at 50 rows, with a line saying how many were omitted. The
counts of all three states are always shown, the JSON export always contains
every port, and the HTML report is never cut short.

**Alternatives:** Always list every port.

**Why:** A default scan covers 1024 ports and nearly all of them are closed. A
table with a thousand dim rows hides the few rows that matter. During the scan
the live table only shows the newest rows that fit on the screen, because a
`Live` display taller than the terminal cannot scroll. The final table, sorted
by port, is printed once the scan ends.

The 50 row cap exists because `--show-all` on a default scan would otherwise
print 1024 rows and push the summary panel off the screen. When rows have to
be dropped, closed and filtered rows go first, so open ports stay visible.
Anyone who needs every row can use the exports or `--plain`, which is not
capped because it is meant to be read by other programs.

## 10. Plain mode writes results to stdout and everything else to stderr

**Decision:** With `--plain`, each result is one tab separated line on stdout.
The permission notice, warnings and the summary go to stderr. Rich is imported
inside the function that uses it, so plain mode never loads it.

**Alternatives:** Print everything to stdout; detect a pipe automatically
instead of having a flag.

**Why:** The point of plain mode is that another program can read it.
`./run.sh host --plain | cut -f1` should give port numbers and nothing else,
and the notice is still shown to the person at the terminal. An explicit flag
is more predictable than guessing from whether stdout is a terminal. Lines are
printed as ports finish, so they are not in port order. Pipe through `sort -n`
if order matters.

## 11. Ctrl-C handling

**Decision:** On `KeyboardInterrupt`, set a stop flag, call
`pool.shutdown(wait=True, cancel_futures=True)`, collect whatever results are
already in the queue, then print the normal table and summary marked as
interrupted. Exports are still written. The exit code is 130.

**Alternatives:** Exit immediately with `os._exit`; let the traceback print.

**Why:** A long scan that is stopped early has still found useful results, and
throwing them away is annoying. `cancel_futures=True` drops every port that
has not started. Ports already in flight cannot be interrupted from Python,
but each one ends within one socket timeout, so waiting for them takes about a
second at the default settings and leaves no half-open sockets behind.

## 12. IPv4 only

**Decision:** The target is resolved with `socket.gethostbyname` and sockets
are `AF_INET`.

**Alternatives:** `socket.getaddrinfo` and scanning IPv6 addresses too.

**Why:** Supporting both means deciding what to do when a name has several
addresses in both families, and reporting results per address. That is a real
feature, not a one line change, and it is listed as a limitation instead.

## 13. Banner grabbing is a correctness check, not just a feature

**Decision:** Treat the banner as evidence about whether an open result is
real, and document it that way. An open port with a banner is confirmed. An
open port with no banner is reported as open, because that is what the
handshake said, but the docs explain that it is a weaker result.

**Alternatives:** Present `--banner` only as a convenience for seeing version
strings; add a fourth "open but unverified" state; turn banner grabbing on by
default.

**Why:** A connect scan only learns that something completed the handshake.
It cannot tell whether that was the target or a device on the path answering
for it. During testing, `scanme.nmap.org` showed ports 135 and 445 as open
from one network and filtered from another, while 3389 was closed from both.
Nothing in the `connect_ex` result separates those false positives from real
open ports. The banner did: 22 and 80 returned OpenSSH 6.6.1p1 and
Apache 2.4.7, and the doubtful ports returned nothing. Reading data from the
service is the only step in the scan that needs a real application on the
other end, so it is the only client-side check on the open state.

A separate "unverified" state was rejected because silence is not proof. Many
real services say nothing until the client speaks their protocol, TLS ports
are skipped on purpose, and the scanner only has a probe for HTTP. Marking all
of those as unverified would bury the suspicious cases among normal ones.
Banner grabbing stays off by default because it sends data to the service and
adds up to one timeout for every silent open port. The limitation and the way
to check for it are written up in `docs/how-it-works.md`.
