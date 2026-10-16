#!/usr/bin/env python3
"""Find the email security gateway (or mailbox host) behind every address in a list, from MX records.

    python detect.py emails.txt -o out.json
    python detect.py emails.txt -o out.csv

Input: one address per line, or any CSV (the first address on each line is used).
Output: email, gateway, kind, mx per address (JSON array for .json, else CSV). Zero dependencies, Python 3.8+.
"""
import argparse, asyncio, collections, csv, json, random, re, socket, struct, sys, time

# Alternating operators, so the retry always lands on a different one. Quad9 is left out on purpose:
# 9.9.9.9 answers NXDOMAIN for threat-listed domains, and 9.9.9.10 throttles bulk runs.
RESOLVERS = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]

# "kind label: suffixes". An MX host takes the label of its longest matching suffix (a full host works too).
VENDORS = """
SEG Mimecast: mimecast.com mimecast.co.za mimecast-offshore.com
SEG Barracuda: barracudanetworks.com
SEG Proofpoint: pphosted.com gpphosted.com ppe-hosted.com
SEG Cisco: iphmx.com
SEG Trend Micro: tmes.trendmicro.com tmes.trendmicro.eu tmes-anz.trendmicro.com tmes-sg.trendmicro.com tmes-in.trendmicro.com tmes-uae.trendmicro.com tmes-uk.trendmicro.com tmes-ca.trendmicro.com tmes-za.trendmicro.com tmes-id.trendmicro.com tmems-jp.trendmicro.com
SEG Sophos: prod.hydra.sophos.com ctr.sophos.com
SEG Symantec: messagelabs.com
SEG Forcepoint: mailcontrol.com
SEG Hornetsecurity: hornetsecurity.com antispameurope.com vadesecure.com
SEG SpamTitan: spamtitan.com titanhq.com
SEG Trellix: fireeyecloud.com
SEG Cloudflare Email Security: cf-emailsecurity.net mxrecord.io mxrecord.mx
SEG Zix: arsmtp.com
SEG N-able: mtaroutes.com spamexperts.com spamexperts.net spamexperts.eu antispamcloud.com
SEG Libraesva: esvacloud.com
SEG Fortinet: fortimail.com fortimailcloud.com
SEG VIPRE: mailanyone.net mx25.net
SEG Mailprotector: shield.security emailservice.io emailservice.cc emailservice.co
SEG Mesh: emailsecurity.app
SEG MX Guarddog: ik2.com ik2.io ik2.eu junkemailfilter.com junkemailfilter.net junkemailfilter.org
SEG SpamHero: spamhero.com spamhero.net mxthunder.com mxthunder.net
SEG SpamStopsHere: spamh.com
SEG GoSecure: gosecure.net zerospam.ca eprism-cloud.com
SEG Securence: securence.com
SEG MailGuard: mailguard.com.au
SEG EveryCloud: everycloudtech.com
SEG Topsec: topsec.com
SEG Heimdal: heimdalsecurity.com
SEG Mailinblack: mailinblack.com
SEG Altospam: altospam.com altospam.net
SEG MailRoute: mailroute.net mroute.net
SEG Retarus: retarus.com
SEG Trustwave: mailmarshal.cloud
SEG MailChannels: mailchannels.net
SEG Intermedia: mx.o365.serverdata.net
mailbox Google: google.com googlemail.com smtp.goog
mailbox Outlook: mail.protection.outlook.com mail.eo.outlook.com olc.protection.outlook.com mx.microsoft mail.protection.office365.us mail.protection.partner.outlook.cn mail.protection.outlook.de pamx1.hotmail.com
mailbox Zoho: zoho.com zoho.eu zoho.in zoho.com.au zoho.jp zoho.com.cn zohocloud.ca zohomail.com zoho.sa zoho.uk
mailbox GoDaddy: smtp.secureserver.net mailstore1.secureserver.net mailstore1.europe.secureserver.net mailstore1.asia.secureserver.net
mailbox Yahoo: yahoodns.net
mailbox iCloud: mail.icloud.com
mailbox Fastmail: messagingengine.com
mailbox Proton: protonmail.ch
mailbox Rackspace: emailsrvr.com
mailbox Intermedia: serverdata.net
mailbox SiteGround: mailspamprotection.com
forwarder Google Domains forwarding: gmr-smtp-in.l.google.com
forwarder Cloudflare Email Routing: mx.cloudflare.net
forwarder ImprovMX: improvmx.com
forwarder Forward Email: forwardemail.net
forwarder Mailgun: mailgun.org
forwarder Porkbun forwarding: fwd1.porkbun.com fwd2.porkbun.com
forwarder Namecheap forwarding: eforward1.registrar-servers.com eforward2.registrar-servers.com eforward3.registrar-servers.com eforward4.registrar-servers.com eforward5.registrar-servers.com
retired Postini (retired): psmtp.com
retired McAfee MX Logic (retired): mxlogic.net mxlogicmx.net
retired Trend Micro (retired): hes.trendmicro.com hes.trendmicro.eu
"""
SUFFIX = {}
for _line in VENDORS.strip().splitlines():
    _head, _keys = _line.split(":")
    _kind, _label = _head.split(" ", 1)
    SUFFIX.update((k, (_label, _kind)) for k in _keys.split())

FIELDS = ("email", "gateway", "kind", "mx")                    # mx = the host that decided the label
RANK = {"SEG": 0, "mailbox": 1, "forwarder": 2, "retired": 3, "custom": 4, "none": 5}
EMAIL = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@([^\s,;:<>\"'()\[\]@]+)")
EDNS = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)          # OPT record: 1232-byte UDP answers


def vendor(host):
    """One MX host -> (label, kind)."""
    if not host or host == "localhost" or host.endswith(".invalid"):
        return "NoMail", "none"                                 # null MX (RFC 7505) or an unroutable target
    if host.startswith("inbound-smtp.") and host.endswith(".amazonaws.com"):
        return "Amazon WorkMail", "mailbox"
    parts = host.split(".")
    for i in range(len(parts) - 1):
        hit = SUFFIX.get(".".join(parts[i:]))
        if hit:
            return hit
    return "Custom", "custom"


def classify(mx):
    """[(preference, host)] -> (label, kind, deciding host). Mail goes to the lowest preference; a gateway wins ties."""
    mx = [(p, h) for p, h in mx if not h.endswith("mx-verification.google.com")]   # Workspace ownership token
    if not mx:
        return "NoMX", "none", ""
    top = min(p for p, _ in mx)
    return min((vendor(h) + (h,) for p, h in sorted(mx) if p == top), key=lambda v: RANK[v[1]])


def norm(domain):
    """Email domain -> ASCII name to query, or None if it can't be one."""
    try:
        d = domain.strip(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return d if "." in d and len(d) <= 253 else None


def read_emails(lines):
    """-> (email, raw domain) per line holding an address; (text, None) for a line with an unusable @."""
    for line in lines:
        m = EMAIL.search(line)
        if m:
            yield m.group(0), m.group(1)
        elif "@" in line:
            yield line.strip(), None


def build(qid, name):
    q = b"".join(bytes([len(l)]) + l for l in name.encode("ascii").split(b".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1) + q + b"\x00\x0f\x00\x01" + EDNS


def name_at(buf, off):
    labels, end, jumps = [], None, 0
    while True:
        n = buf[off]
        if n >= 0xC0:                                           # compression pointer
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | buf[off + 1]
            jumps += 1
            if jumps > 32:
                raise ValueError("pointer loop")
            continue
        off += 1
        if n == 0:
            return ".".join(labels), (end if end is not None else off)
        labels.append(buf[off:off + n].decode("ascii", "replace"))
        off += n


def parse(buf):
    """DNS answer -> (qid, rcode, truncated, qname, [(preference, mx host)])."""
    qid, flags, qd, an = struct.unpack_from(">HHHH", buf)
    off, qname = 12, ""
    for _ in range(qd):
        qname, off = name_at(buf, off)
        off += 4
    tc, recs = bool(flags & 0x200), []
    for _ in range(0 if tc else an):                            # a truncated answer is re-asked over TCP
        _, off = name_at(buf, off)
        rtype, _, _, rdlen = struct.unpack_from(">HHIH", buf, off)
        off += 10
        if rtype == 15:
            recs.append((struct.unpack_from(">H", buf, off)[0], name_at(buf, off + 2)[0].lower()))
        off += rdlen
    return qid, flags & 0xF, tc, qname.lower(), recs


class _Proto(asyncio.DatagramProtocol):
    def __init__(self):
        self.pending = {}                                       # qid -> (future, server, qname)

    def datagram_received(self, data, addr):
        try:
            qid, rcode, tc, qname, recs = parse(data)
        except Exception:
            return
        p = self.pending.get(qid)
        if p and p[1] == addr[0] and p[2] == qname and not p[0].done():
            p[0].set_result((rcode, tc, recs))

    def error_received(self, exc):
        pass


async def resolve_all(domains, servers, conc, timeout):
    """-> {domain: (status, [(preference, host)])}, status in ok | nx | servfail | timeout."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        sock.ioctl(socket.SIO_UDP_CONNRESET, False)             # Windows: ignore ICMP port-unreachable resets
    sock.bind(("0.0.0.0", 0))
    transport, proto = await loop.create_datagram_endpoint(_Proto, sock=sock)
    out = {}

    async def tcp(name, srv):
        r, w = await asyncio.open_connection(srv, 53)
        try:
            q = build(random.getrandbits(16), name)
            w.write(struct.pack(">H", len(q)) + q)
            n, = struct.unpack(">H", await r.readexactly(2))
            _, rcode, _, _, recs = parse(await r.readexactly(n))
            return rcode, recs
        finally:
            w.close()

    async def query(name, srv):
        qid = random.getrandbits(16)
        while qid in proto.pending:
            qid = random.getrandbits(16)
        fut = loop.create_future()
        proto.pending[qid] = (fut, srv, name)
        try:
            transport.sendto(build(qid, name), (srv, 53))
            rcode, tc, recs = await asyncio.wait_for(fut, timeout)
        finally:
            del proto.pending[qid]
        return await asyncio.wait_for(tcp(name, srv), 2 * timeout) if tc else (rcode, recs)

    async def lookup(i, d):
        status = "timeout"
        for attempt in range(2):
            try:
                rcode, recs = await query(d, servers[(i + attempt) % len(servers)])
            except (asyncio.TimeoutError, OSError, EOFError, ValueError, struct.error):
                continue
            if rcode == 0:
                return "ok", recs
            if rcode == 3:
                return "nx", []
            status = "servfail"
        return status, []

    async def pool(names, n):
        it = iter(enumerate(names))

        async def worker():
            for i, d in it:
                out[d] = await lookup(i, d)
        await asyncio.gather(*(worker() for _ in range(max(1, min(n, len(names))))))

    try:
        await pool(domains, conc)
        again = [d for d in domains if out[d][0] == "timeout"]
        if again:
            await pool(again, max(1, conc // 4))                # gentler second pass: most are burst losses
    finally:
        transport.close()
    return out


def main():
    ap = argparse.ArgumentParser(description="Detect the email gateway (Mimecast, Barracuda, Proofpoint, ...) "
                                             "or mailbox host (Google, Outlook, ...) behind each email address.")
    ap.add_argument("input", nargs="?", default="-", help="file of emails, plain or CSV (default: stdin)")
    ap.add_argument("-o", "--output", default="-", help="CSV file to write (default: stdout)")
    ap.add_argument("-c", "--concurrency", type=int, default=1024, help="DNS queries in flight (default 1024)")
    ap.add_argument("-t", "--timeout", type=float, default=2.5, help="seconds per DNS try (default 2.5)")
    ap.add_argument("-r", "--resolver", action="append",
                    help="IPv4 DNS server to use, repeatable (default: Cloudflare + Google)")
    a = ap.parse_args()

    if a.input == "-":
        sys.stdin.reconfigure(encoding="utf-8-sig", errors="replace")
        src = sys.stdin
    else:
        with open(a.input, "rb") as f:
            bom = f.read(2)                                     # PowerShell 5.1 '>' writes UTF-16
        src = open(a.input, encoding="utf-16" if bom in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig",
                   errors="replace")
    rows = [(email, norm(d) if d else None) for email, d in read_emails(src)]
    domains = list(dict.fromkeys(d for _, d in rows if d))

    t0 = time.perf_counter()
    res = asyncio.run(resolve_all(domains, a.resolver or RESOLVERS, a.concurrency, a.timeout))
    secs = time.perf_counter() - t0

    if a.output == "-":
        sys.stdout.reconfigure(encoding="utf-8")
        out = sys.stdout
    else:
        out = open(a.output, "w", encoding="utf-8", newline="")
    results, tally = [], collections.Counter()
    for email, d in rows:
        status, recs = res[d] if d else ("invalid", [])
        if status == "ok":
            label, kind, host = classify(recs)
        else:
            label, kind, host = {"nx": "NXDOMAIN", "servfail": "SERVFAIL", "timeout": "Timeout"}.get(status, "Invalid"), "none", ""
        results.append((email, label, kind, host))
        tally[label] += 1
    if a.output.lower().endswith(".json"):
        out.write("[\n" + ",\n".join("  " + json.dumps(dict(zip(FIELDS, r)), ensure_ascii=False) for r in results) + "\n]\n")
    else:
        w = csv.writer(out, lineterminator="\n")
        w.writerow(FIELDS)
        w.writerows(results)
    out.flush()

    print(f"{len(rows)} emails, {len(domains)} domains, {secs:.1f}s ({len(domains) / max(secs, 1e-9):.0f} domains/s)",
          file=sys.stderr)
    for label, n in tally.most_common():
        print(f"{n:>9}  {label}", file=sys.stderr)


if __name__ == "__main__":
    main()
