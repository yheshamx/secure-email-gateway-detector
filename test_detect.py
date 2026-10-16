"""Offline checks, no network: python test_detect.py (pytest works too)."""
import struct

from detect import build, classify, norm, parse, read_emails


def test_classify():
    cases = [
        ("Mimecast", [(10, "eu-smtp-inbound-1.mimecast.com"), (10, "eu-smtp-inbound-2.mimecast.com")]),
        ("Mimecast", [(10, "za-smtp-inbound-1.mimecast.co.za")]),
        ("Barracuda", [(10, "d123456a.ess.barracudanetworks.com"), (20, "d123456b.ess.barracudanetworks.com")]),
        ("Proofpoint", [(10, "mx0a-001b2d05.pphosted.com")]),
        ("Proofpoint", [(10, "mxa.gslb.gpphosted.com")]),               # federal
        ("Proofpoint", [(10, "mx1-us1.ppe-hosted.com")]),               # Essentials
        ("Cisco", [(10, "mx1.hc1234-56.iphmx.com")]),
        ("Google", [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")]),
        ("Google", [(1, "smtp.google.com")]),
        ("Google", [(5, "gmail-smtp-in.l.google.com")]),
        ("Outlook", [(0, "contoso-com.mail.protection.outlook.com")]),
        ("Outlook", [(0, "contoso-com.x-v1.mx.microsoft")]),             # new DNSSEC hosts
        ("Outlook", [(10, "abc.pamx1.hotmail.com")]),                    # legacy Outlook.com custom domain
        ("Outlook", [(10, "contoso-de.mail.protection.outlook.de")]),
        ("Amazon WorkMail", [(10, "inbound-smtp.eu-west-1.amazonaws.com")]),
        ("GoDaddy", [(0, "smtp.secureserver.net"), (10, "mailstore1.secureserver.net")]),
        ("Intermedia", [(10, "east.smtp.mx.o365.serverdata.net")]),
        ("Google Domains forwarding", [(5, "gmr-smtp-in.l.google.com")]),
        ("Postini (retired)", [(10, "example.com.s7a1.psmtp.com")]),
        # lowest preference decides
        ("Google", [(1, "aspmx.l.google.com"), (98, "mx1-us1.ppe-hosted.com")]),
        ("Proofpoint", [(10, "mx0a-1.pphosted.com"), (99, "x.mail.protection.outlook.com")]),
        ("Custom", [(100, "mapper.example.com"), (200, "mx0a-1.pphosted.com")]),
        # a tie at the lowest preference: the gateway wins
        ("Sophos", [(0, "x.mail.protection.outlook.com"), (0, "mx-01-eu-west-1.prod.hydra.sophos.com")]),
        # suffix, never substring
        ("Custom", [(10, "mx.barracuda.company.example")]),
        ("Custom", [(10, "mail.notoutlook.com")]),
        ("Custom", [(10, "mx.google.com.attacker.net")]),
        ("Custom", [(10, "aspmx2.googlemail.com.example.com")]),         # missing trailing dot in the zone file
        ("Custom", [(10, "sxb1plzcpnl1.prod.sxb1.secureserver.net")]),   # GoDaddy web hosting, not GoDaddy mail
        ("Custom", [(10, "feedback-smtp.eu-west-1.amazonses.com")]),
        # no mail at all
        ("NoMail", [(0, "")]),
        ("NoMail", [(0, "localhost")]),
        ("NoMail", [(0, "abc.msv1.invalid")]),
        ("NoMX", []),
        ("NoMX", [(15, "abcdef.mx-verification.google.com")]),
        ("Google", [(1, "smtp.google.com"), (15, "abcdef.mx-verification.google.com")]),
    ]
    for want, mx in cases:
        assert classify(mx)[0] == want, (want, mx, classify(mx))
    assert classify([(10, "eu-smtp-inbound-1.mimecast.com")])[1] == "seg"
    assert classify([(1, "aspmx.l.google.com")])[1] == "mailbox"
    assert classify([(10, "mx.example.com")])[1] == "custom"


def test_parse():
    q = b"\x07example\x03com\x00"
    head = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0) + q + b"\x00\x0f\x00\x01"
    mx1 = struct.pack(">H", 10) + b"\x02mx\xc0\x0c"                    # mx.<pointer to example.com>
    mx2 = struct.pack(">H", 0) + b"\x00"                               # null MX
    ans = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 300, len(r)) + r for r in (mx1, mx2))
    assert parse(head + ans) == (0x1234, 0, False, "example.com", [(10, "mx.example.com"), (0, "")])
    nx = struct.pack(">HHHHHH", 7, 0x8183, 1, 0, 0, 0) + q + b"\x00\x0f\x00\x01"
    assert parse(nx)[1] == 3
    tc = struct.pack(">HHHHHH", 8, 0x8380, 1, 5, 0, 0) + q + b"\x00\x0f\x00\x01"   # truncated, answers cut off
    assert parse(tc) == (8, 0, True, "example.com", [])
    assert parse(build(99, "example.com"))[:4] == (99, 0, False, "example.com")


def test_inputs():
    lines = ["email,name\n", '"Bob","BOB@Example.COM"\n', "mailto:jo@x.co\n", "bad@\n", "nothing here\n",
             "﻿ann@müller.de\n"]
    got = list(read_emails(lines))
    assert got == [("BOB@Example.COM", "Example.COM"), ("jo@x.co", "x.co"), ("bad@", None),
                   ("ann@müller.de", "müller.de")], got
    assert norm("Example.COM.") == "example.com"
    assert norm("müller.de") == "xn--mller-kva.de"
    assert norm("a..b") is None and norm("localhost") is None


if __name__ == "__main__":
    test_classify(); test_parse(); test_inputs()
    print("ok")
