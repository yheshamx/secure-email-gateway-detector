# secure-email-gateway-detector

Find out which email security gateway sits in front of every inbox on your list.

```
                    ┌──────────────┐
  your email  ────▶ │   gateway    │ ────▶  their inbox
                    └──────────────┘
                 Mimecast? Barracuda?
                 Proofpoint? Google?
```

```
  your list            MX record (DNS)            result
  ───────────────      ─────────────────────      ─────────────────────
  a@ibm.com        ──▶ pphosted.com           ──▶ Proofpoint    SEG
  b@chevron.com    ──▶ iphmx.com              ──▶ Cisco         SEG
  c@barracuda.com  ──▶ barracudanetworks.com  ──▶ Barracuda     SEG
  e@gmail.com      ──▶ google.com             ──▶ Google        mailbox
  f@microsoft.com  ──▶ outlook.com            ──▶ Outlook       mailbox
```

It's one Python file with nothing to install, and 10,000 contacts take about 13 seconds.

## Run it

```sh
python detect.py emails.txt -o out.json
```

Use `-o out.csv` for a spreadsheet instead. The input is one email per line, or any CSV (it takes the first email on each line). You need Python 3.8+. No Python on Windows? Run `winget install Python.Python.3.13`, then use `py` instead of `python`.

## Output

```json
[
  {"email": "a@ibm.com", "gateway": "Proofpoint", "kind": "SEG", "mx": "mx0a-001b2d05.pphosted.com"},
  {"email": "e@gmail.com", "gateway": "Google", "kind": "mailbox", "mx": "gmail-smtp-in.l.google.com"}
]
```

- `gateway`: the vendor, or `Custom` for the company's own mail server
- `kind`: `SEG` (secure email gateway), `mailbox`, `forwarder`, `retired`, `custom` or `none`
- `mx`: the mail server that decided the label

If a domain can't take mail, `gateway` says why: `NoMX`, `NoMail`, `NXDOMAIN`, `SERVFAIL`, `Timeout` (run it again) or `Invalid`.

## What it detects

```
SEG        Mimecast, Barracuda, Proofpoint, Cisco, Sophos, Trend Micro, Symantec,
           Forcepoint, Hornetsecurity, Trellix, Fortinet and 24 more
mailbox    Google, Outlook, Zoho, GoDaddy, Yahoo, iCloud, Proton and 5 more
forwarder  Cloudflare Email Routing, ImprovMX, Namecheap forwarding and 4 more
```

The full list is the `VENDORS` block at the top of `detect.py`. Add a line there to add a vendor.

It labels the MX host that mail goes to first (lowest preference), and a gateway wins a tie.

## Speed

10,000 contacts on 10,000 different domains took 12.1 to 13.3 seconds over 3 runs (Windows laptop, home internet). Repeated domains are faster, because each domain is looked up once.

Options: `-c` queries in flight (default 1024), `-t` seconds per try (default 2.5), `-r` DNS server (default Cloudflare + Google).

## Limits

- Security tools that connect by API instead of MX (Abnormal, IRONSCALES and similar) don't show up. You'll see the mailbox host.
- A gateway behind the company's own hostname shows as `Custom`.

## License

MIT
