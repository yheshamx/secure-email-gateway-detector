# sender-email-gateway-detector

Give it a list of email addresses. It tells you which email security gateway (Mimecast, Barracuda, Proofpoint, Cisco and 30 more) or mailbox host (Google, Outlook, Zoho and others) receives the mail for each one.

One Python file. Nothing to install. About 2,300 domains a second.

## Run it

```
python detect.py emails.txt -o out.csv
```

`emails.txt` can be one address per line or any CSV. It takes the first address on each line, so header rows and extra columns are fine. Leave out `-o` to print to the screen, or pipe the list in: `python detect.py < emails.csv`.

Needs Python 3.8 or newer.

## What you get

```
email,domain,gateway,kind,mx
x@mimecast.com,mimecast.com,Mimecast,seg,10:service-alpha-inbound-a.mimecast.com 10:service-alpha-inbound-b.mimecast.com
x@barracuda.com,barracuda.com,Barracuda,seg,10:d160221a.ess.barracudanetworks.com 20:d160221b.ess.barracudanetworks.com
x@ibm.com,ibm.com,Proofpoint,seg,5:mx0a-001b2d05.pphosted.com 5:mx0b-001b2d05.pphosted.com
x@chevron.com,chevron.com,Cisco,seg,10:mx1.hc2860-13.iphmx.com 10:mx2.hc2860-13.iphmx.com
x@microsoft.com,microsoft.com,Outlook,mailbox,10:microsoft-com.mail.protection.outlook.com
x@example.com,example.com,NoMail,none,0:.
```

| Column | Meaning |
|---|---|
| `gateway` | Who receives the mail first: a vendor name, `Custom` (the company's own server, or one not in the list), or a status below |
| `kind` | `seg` (security gateway), `mailbox`, `forwarder`, `retired`, `custom` or `none` |
| `mx` | Every MX record for the domain, as `preference:host` |

Statuses in the `gateway` column:

| Status | Meaning |
|---|---|
| `NoMX` | The domain exists but has no MX record |
| `NoMail` | The domain publishes a null MX: it takes no mail |
| `NXDOMAIN` | The domain doesn't exist |
| `SERVFAIL` | The domain's own DNS is broken |
| `Timeout` | No DNS answer. Run those rows again |
| `Invalid` | Not a usable email address |

When it finishes it prints a count per label.

## Labels

| Kind | Labels |
|---|---|
| seg | Mimecast, Barracuda, Proofpoint, Cisco, Trend Micro, Sophos, Symantec, Forcepoint, Hornetsecurity, SpamTitan, Trellix, Cloudflare Email Security, Zix, N-able, Libraesva, Fortinet, VIPRE, Mailprotector, Mesh, MX Guarddog, SpamHero, SpamStopsHere, GoSecure, Securence, MailGuard, EveryCloud, Topsec, Heimdal, Mailinblack, Altospam, MailRoute, Retarus, Trustwave, MailChannels, Intermedia |
| mailbox | Google, Outlook, Zoho, GoDaddy, Yahoo, iCloud, Fastmail, Proton, Rackspace, Intermedia, SiteGround, Amazon WorkMail |
| forwarder | Google Domains forwarding, Cloudflare Email Routing, ImprovMX, Forward Email, Mailgun, Porkbun forwarding, Namecheap forwarding |
| retired | Postini, McAfee MX Logic, old Trend Micro hosts |

`Outlook` covers Microsoft 365, Exchange Online and consumer Outlook/Hotmail. The full host list is the `VENDORS` block at the top of `detect.py`. To add a vendor, add a line.

## How it decides

1. It dedupes domains first, so 100,000 gmail.com addresses cost one lookup.
2. It asks Cloudflare and Google public DNS for MX records, 1,024 queries at a time. A failed query retries on the other provider, and anything that timed out gets a second, slower pass.
3. It labels the MX host with the lowest preference number, because that's where senders deliver first. If hosts tie, a security gateway beats a mailbox host.
4. It matches the end of the hostname, never a substring. `mx.google.com.attacker.net` is Custom, not Google.

## Speed

On a Windows 11 laptop on home internet, 50,000 domains from the Tranco top-1M list took 21.9 seconds (about 2,300 domains a second). Your network sets the real limit.

| Option | Default | What it does |
|---|---|---|
| `-c` | 1024 | DNS queries in flight |
| `-t` | 2.5 | Seconds per DNS try |
| `-r` | 1.1.1.1, 8.8.8.8, 1.0.0.1, 8.8.4.4 | DNS server to use. Repeat it for several. IPv4 only |

If your network blocks outside DNS, point `-r` at your own resolver. Quad9 is left out on purpose. 9.9.9.9 answers NXDOMAIN for domains on its threat list, and 9.9.9.10 throttled bulk runs in testing.

## What it can't see

- Security tools that plug in through an API instead of MX (Abnormal, Check Point Harmony, IRONSCALES, INKY and similar). Those domains show their mailbox host.
- A gateway behind the company's own hostname, like an on-prem Barracuda at `mx.company.com` or a vanity name pointed at a vendor. Those show as Custom.
- Changes after you run it. Companies switch vendors, so run it fresh.

## Tests

```
python test_detect.py
```

Offline, no network needed.

## Credits

Hostnames were checked against vendor docs and live DNS, and cross-checked with [jace/mxsniff](https://github.com/jace/mxsniff) (BSD-2-Clause), [Viktopia/email-service-checker](https://github.com/Viktopia/email-service-checker) (MIT) and [kkrlstrm/gtm-deliverability](https://github.com/kkrlstrm/gtm-deliverability) (Apache-2.0).

## License

MIT
