---
title: How it works
---

# How it works

## The TCP connect scan

Every TCP connection starts with a three-way handshake:

```
scanner                          target
   | -------- SYN ----------------> |    "I want to connect to port N"
   | <------- SYN/ACK ------------- |    "OK, port N is listening"
   | -------- ACK ----------------> |    "Connection established"
```

A connect scan simply asks the operating system to open a normal connection to
each port, using the same `connect()` call a browser or an SSH client uses.
The kernel does the handshake, and the scanner looks at how the attempt ended.
If the connection was established, the scanner closes it again straight away
(or reads a banner first when `--banner` is set).

Because it uses the normal socket API, a connect scan needs no special
privileges. Its faster relative, the SYN scan, sends the SYN, reads the reply
and never sends the final ACK. That requires building packets by hand with raw
sockets, which needs root, so this scanner does not do it.

For each port the scanner creates a socket, sets a timeout, and calls
`connect_ex((ip, port))`. `connect_ex` is the same as `connect` except that it
returns an error number instead of raising an exception. The ports are spread
over a pool of threads so that many attempts are in flight at once.

## The three port states

**Open.** The target answers the SYN with SYN/ACK and the handshake completes.
`connect_ex` returns `0`. A program is listening on that port and accepting
connections.

```
SYN ->      <- SYN/ACK      ACK ->        connect_ex returns 0
```

**Closed.** The target answers the SYN with a RST (reset) packet. The host is
reachable, but no program is listening on that port. The kernel reports this
as "connection refused", so `connect_ex` returns `errno.ECONNREFUSED`. The
answer arrives as fast as an open port's would.

```
SYN ->      <- RST                        connect_ex returns ECONNREFUSED
```

**Filtered.** Nothing useful comes back. Usually a firewall is silently
dropping the SYN, so the scanner waits until the timeout runs out. Sometimes a
router sends back an ICMP "unreachable" message instead, which shows up as a
different error such as `EHOSTUNREACH`. The scanner treats a timeout and every
error other than `ECONNREFUSED` as filtered.

```
SYN ->      (silence)                     timeout, or some other error
```

Closed and filtered are kept apart because they mean different things. A
closed port proves that the host is up and that the packet reached it. A
filtered port proves neither: the port might be open behind a firewall, or the
host might not exist at all. Filtered ports are also why scans of firewalled
hosts are slow, because each one costs a full timeout.

One more state can appear, `error`. It means the scanner itself could not
create a socket because it ran out of file descriptors. It says nothing about
the target, so those ports are counted separately.

## Banner grabbing

With `--banner`, the scanner reads the first bytes an open port sends. Some
protocols speak first (SSH, FTP, SMTP), so the scanner only has to read.
HTTP servers wait for a request, so on HTTP ports the scanner first sends
`HEAD / HTTP/1.0` and then reads the status line and the `Server` header. TLS
ports such as 443 are skipped, because without a TLS handshake they return
nothing readable.

## Limitations

- **No UDP.** Only TCP is scanned. Services that use UDP, such as DNS, DHCP,
  NTP and SNMP, are invisible to it.
- **No version detection.** The service column is looked up from the port
  number alone. Port 22 is labelled "ssh" even if something else is running
  there. Banners help, but they are whatever the server chooses to say, and
  only plain text banners are shown.
- **No OS fingerprinting.** The scanner does not try to work out the target's
  operating system.
- **IPv4 only.** Hostnames are resolved to a single IPv4 address. IPv6
  addresses, and any extra addresses behind the same name, are not scanned.
- **NAT and middleboxes can confuse the results.** The scanner only sees what
  answers at the address it was given. Behind NAT that is the router and
  whatever ports it forwards, not the machines behind it. Firewalls, load
  balancers and transparent proxies can answer on behalf of the target, so a
  port may look open when the real host is not listening, or closed when the
  firewall is just sending resets.
- **It reports what the network path allows, not what the target runs.**
  "Open" only means that something completed the handshake. That something
  can be a device in between, such as an ISP filter, a corporate firewall or a
  transparent proxy, answering the SYN on the target's behalf. The client sees
  an ordinary SYN/ACK and `connect_ex` returns 0, so this false positive
  cannot be detected from the connection itself.

  This was observed while testing against `scanme.nmap.org`, which the Nmap
  project provides for test scans. Scanned from two different networks, ports
  135 and 445 were open from one and filtered from the other, while 3389 was
  closed from both. The same host cannot have a port both open and filtered,
  so on at least one of those networks the answer came from the path and not
  from the target. With `--banner`, ports 22 and 80 returned real banners
  (OpenSSH 6.6.1p1 and Apache 2.4.7), and the "open" 135 and 445 returned
  nothing.

  A missing banner on a port that should have one is the only tell available
  from the client side. A banner shows that a real service is on the other
  end. An open port that should greet the client and stays silent deserves
  suspicion. It is a hint and not proof, because some services never send
  anything until the client speaks their protocol. The services normally found
  on 135 and 445 are like that, and this scanner has no probe for them. The
  reliable check is to scan again from a different network and compare.
- **Trivially detectable.** A connect scan completes the full handshake on
  every open port, so connections show up in the target's application logs,
  and hundreds of attempts from one address in a few seconds are easy for any
  firewall or intrusion detection system to notice. There is no attempt at
  stealth, and there should not be: only scan systems you own or have written
  permission to test.
- **Filtered is a guess.** A timeout looks the same whether a firewall dropped
  the packet, the host is down, or the network was just slow. A timeout that
  is too short for the link will turn open ports into filtered ones.
- **No rate control.** The only speed controls are `--workers` and
  `--timeout`. A large worker count can overwhelm small devices such as home
  routers, or trigger rate limiting that makes closed ports look filtered.
