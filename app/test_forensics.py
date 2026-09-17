import reflex as rx
import hashlib
import unittest
from unittest.mock import patch, AsyncMock
from app.states.parser import (
    parse_message,
    public_addresses,
    extract_links,
    MAX_BYTES,
)
from app.states.evidence import Finding
from app.states.dns_service import enrich
from app.states.report_service import build_pdf


RAW = b"From: Analyst <a@example.com>\r\nReply-To: b@example.net\r\nSubject: Evidence\r\nMessage-ID: <case@example.com>\r\nReceived: from gateway [8.8.8.8] by relay; now\r\nReceived: from source (2606:4700:4700::1111) by gateway; before\r\nReceived: from local [192.168.0.1] by source; earlier\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nVisit https://example.com/a and http://8.8.8.8/path."


class EvidenceTests(unittest.TestCase):
    def test_wire_order_and_integrity(self):
        report = parse_message(RAW, "evidence.eml", "Analyst")
        self.assertEqual(len(report.hops), 3)
        self.assertIn("gateway", report.hops[0].raw)
        self.assertEqual(report.public_ips, ["8.8.8.8", "2606:4700:4700::1111"])
        self.assertEqual(report.sha256, hashlib.sha256(RAW).hexdigest())
        self.assertTrue(report.anomalies)
        self.assertEqual(report.domain, "example.com")

    def test_non_global_exclusions_and_dedup(self):
        self.assertEqual(
            public_addresses(
                "[127.0.0.1] 10.0.0.1 169.254.1.1 192.0.2.1 224.0.0.1 ::1 fe80::1 fc00::1 ff02::1 240.0.0.1 [8.8.8.8] 8.8.8.8"
            ),
            ["8.8.8.8"],
        )
        self.assertEqual(
            public_addresses("[IPv6:2606:4700:4700::1111]"),
            ["2606:4700:4700::1111"],
        )

    def test_clean_links(self):
        links = extract_links(
            '<a href="https://EXAMPLE.com/a?x=1&amp;y=2">open</a> https://example.com/a?x=1&y=2 http://8.8.8.8/path.'
        )
        self.assertEqual(len(links), 2)
        self.assertEqual(links[0].url, "https://example.com/a?x=1&y=2")
        self.assertIn("IP-literal destination", links[1].flags)

    def test_invalid_content(self):
        for raw, filename, prefix in [
            (RAW, "bad.msg", "400:"),
            (b"x" * (MAX_BYTES + 1), "large.eml", "413:"),
            (b"not mail", "bad.eml", "422:"),
        ]:
            with self.assertRaisesRegex(ValueError, prefix):
                parse_message(raw, filename)

    def test_pdf(self):
        report = parse_message(RAW, "evidence.eml")
        self.assertTrue(build_pdf(report).startswith(b"%PDF"))


class DNSTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_not_normalized_into_score(self):
        async def unavailable(name, query):
            return Finding(
                name=name,
                query=query,
                status="unknown",
                detail="Test resolver unavailable",
            )

        with (
            patch("app.states.dns_service.txt_check", side_effect=unavailable),
            patch(
                "app.states.dns_service.check_domain",
                new=AsyncMock(
                    return_value=Finding(name="checkdmarc", status="unknown")
                ),
            ),
        ):
            report = await enrich(parse_message(RAW, "evidence.eml"))
        self.assertEqual(report.factors[1].points, 0)
        self.assertEqual(report.factors[2].points, 0)
        self.assertEqual(report.score, sum(f.points for f in report.factors))
        self.assertIn("0/2", report.coverage)


if __name__ == "__main__":
    unittest.main()
