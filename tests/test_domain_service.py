"""Tests for the DomainSecurityService."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdatatype
import pytest

from app.constants import DomainCheckStatus
from app.services.domain import DomainSecurityService


@pytest.fixture()
def service() -> DomainSecurityService:
    return DomainSecurityService()


# ------------------------------------------------------------------
# extract_domain
# ------------------------------------------------------------------

class TestExtractDomain:
    def test_bare_domain(self, service: DomainSecurityService):
        assert service.extract_domain("example.com") == "example.com"

    def test_with_https(self, service: DomainSecurityService):
        assert service.extract_domain("https://example.com") == "example.com"

    def test_with_http(self, service: DomainSecurityService):
        assert service.extract_domain("http://example.com") == "example.com"

    def test_with_www(self, service: DomainSecurityService):
        assert service.extract_domain("https://www.example.com") == "example.com"

    def test_with_path(self, service: DomainSecurityService):
        assert service.extract_domain("https://example.com/path/to/page") == "example.com"

    def test_with_port(self, service: DomainSecurityService):
        assert service.extract_domain("https://example.com:8080/page") == "example.com"

    def test_trailing_dot(self, service: DomainSecurityService):
        assert service.extract_domain("example.com.") == "example.com"

    def test_uppercase(self, service: DomainSecurityService):
        assert service.extract_domain("HTTPS://WWW.EXAMPLE.COM") == "example.com"


# ------------------------------------------------------------------
# WHOIS check
# ------------------------------------------------------------------

class TestWhoisCheck:
    @pytest.mark.asyncio
    async def test_successful_whois(self, service: DomainSecurityService):
        mock_data = MagicMock()
        mock_data.get = MagicMock(side_effect=lambda key, default=None: {
            "creation_date": datetime(2020, 1, 1, tzinfo=UTC),
            "expiration_date": datetime.now(tz=UTC) + timedelta(days=365),
            "status": ["clientTransferProhibited https://icann.org"],
            "registrar": "GoDaddy.com",
            "name": "REDACTED FOR PRIVACY",
            "org": "Domains By Proxy, LLC",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
        }.get(key, default))

        with patch("app.services.domain.whois.whois", return_value=mock_data):
            result = await service._check_whois("example.com")

        assert result.status == DomainCheckStatus.PASS
        assert result.transfer_locked is True
        assert result.privacy_enabled is True
        assert result.registrar == "GoDaddy.com"
        assert result.days_until_expiry is not None
        assert result.days_until_expiry > 300

    @pytest.mark.asyncio
    async def test_whois_expired_domain(self, service: DomainSecurityService):
        mock_data = MagicMock()
        mock_data.get = MagicMock(side_effect=lambda key, default=None: {
            "creation_date": datetime(2020, 1, 1, tzinfo=UTC),
            "expiration_date": datetime.now(tz=UTC) - timedelta(days=10),
            "status": [],
            "registrar": "Test Registrar",
            "name": "",
            "org": "",
            "name_servers": [],
        }.get(key, default))

        with patch("app.services.domain.whois.whois", return_value=mock_data):
            result = await service._check_whois("expired.com")

        assert result.status == DomainCheckStatus.FAIL
        assert result.days_until_expiry is not None
        assert result.days_until_expiry < 0

    @pytest.mark.asyncio
    async def test_whois_no_transfer_lock(self, service: DomainSecurityService):
        mock_data = MagicMock()
        mock_data.get = MagicMock(side_effect=lambda key, default=None: {
            "creation_date": datetime(2020, 1, 1, tzinfo=UTC),
            "expiration_date": datetime.now(tz=UTC) + timedelta(days=365),
            "status": ["ok"],
            "registrar": "Test Registrar",
            "name": "John Doe",
            "org": "ACME Inc",
            "name_servers": ["ns1.example.com"],
        }.get(key, default))

        with patch("app.services.domain.whois.whois", return_value=mock_data):
            result = await service._check_whois("example.com")

        assert result.status == DomainCheckStatus.WARNING
        assert result.transfer_locked is False
        assert result.privacy_enabled is False

    @pytest.mark.asyncio
    async def test_whois_lookup_error(self, service: DomainSecurityService):
        with patch("app.services.domain.whois.whois", side_effect=Exception("WHOIS timeout")):
            result = await service._check_whois("bad-domain.xyz")

        assert result.status == DomainCheckStatus.ERROR
        assert "WHOIS timeout" in result.error


# ------------------------------------------------------------------
# HSTS check
# ------------------------------------------------------------------

class TestHstsCheck:
    @pytest.mark.asyncio
    async def test_hsts_enabled(self, service: DomainSecurityService):
        mock_response = MagicMock()
        mock_response.headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        }

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.services.domain.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_hsts("example.com")

        assert result.enabled is True
        assert result.max_age == 31536000
        assert result.include_subdomains is True
        assert result.preload is True
        assert result.status == DomainCheckStatus.PASS

    @pytest.mark.asyncio
    async def test_hsts_not_configured(self, service: DomainSecurityService):
        mock_response = MagicMock()
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.services.domain.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_hsts("example.com")

        assert result.enabled is False
        assert result.status == DomainCheckStatus.FAIL

    @pytest.mark.asyncio
    async def test_hsts_low_max_age(self, service: DomainSecurityService):
        mock_response = MagicMock()
        mock_response.headers = {
            "strict-transport-security": "max-age=3600",
        }

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.services.domain.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_hsts("example.com")

        assert result.enabled is True
        assert result.max_age == 3600
        assert result.status == DomainCheckStatus.WARNING

    @pytest.mark.asyncio
    async def test_hsts_connection_error(self, service: DomainSecurityService):
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.services.domain.httpx.AsyncClient", return_value=mock_client):
            result = await service._check_hsts("bad.example.com")

        assert result.status == DomainCheckStatus.ERROR
        assert "Connection refused" in result.error


# ------------------------------------------------------------------
# SSL check
# ------------------------------------------------------------------

class TestSslCheck:
    def test_parse_certificate_valid(self, service: DomainSecurityService):
        cert = {
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subject": ((("commonName", "example.com"),),),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2099 GMT",
        }
        result = service._parse_certificate(cert, "TLSv1.3")

        assert result.issuer == "Let's Encrypt"
        assert result.subject == "example.com"
        assert result.san == ["example.com", "www.example.com"]
        assert result.is_valid is True
        assert result.protocol_version == "TLSv1.3"
        assert result.status == DomainCheckStatus.PASS

    def test_parse_certificate_expired(self, service: DomainSecurityService):
        cert = {
            "issuer": ((("organizationName", "Test CA"),),),
            "subject": ((("commonName", "expired.com"),),),
            "subjectAltName": (),
            "notBefore": "Jan  1 00:00:00 2020 GMT",
            "notAfter": "Jan  1 00:00:00 2021 GMT",
        }
        result = service._parse_certificate(cert, "TLSv1.2")

        assert result.is_valid is False
        assert result.status == DomainCheckStatus.FAIL

    @pytest.mark.asyncio
    async def test_ssl_connection_failure(self, service: DomainSecurityService):
        with patch(
            "app.services.domain.socket.create_connection",
            side_effect=OSError("Connection refused"),
        ):
            result = await service._check_ssl("bad.example.com")

        assert result.status == DomainCheckStatus.FAIL
        assert "Connection refused" in result.error


# ------------------------------------------------------------------
# DNS check
# ------------------------------------------------------------------

class TestDnsCheck:
    @pytest.mark.asyncio
    async def test_dns_all_records_present(self, service: DomainSecurityService):
        def fake_resolve(qname, rdtype):
            mock_answer = MagicMock()
            mock_rrset = MagicMock()
            mock_rrset.ttl = 300
            mock_answer.rrset = mock_rrset

            if rdtype == "A":
                mock_rdata = MagicMock()
                mock_rdata.__str__ = lambda self: "93.184.216.34"
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer
            if rdtype == "AAAA":
                mock_rdata = MagicMock()
                mock_rdata.__str__ = lambda self: "2001:db8::1"
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer
            if rdtype == "MX":
                mock_rdata = MagicMock()
                mock_rdata.__str__ = lambda self: "10 mail.example.com."
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer
            if rdtype == "NS":
                mock_rdata = MagicMock()
                mock_rdata.__str__ = lambda self: "ns1.example.com."
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer
            if rdtype == "TXT":
                if "_dmarc" in str(qname):
                    mock_rdata = MagicMock()
                    mock_rdata.__str__ = lambda self: '"v=DMARC1; p=reject"'
                    mock_answer.__iter__ = lambda self: iter([mock_rdata])
                    return mock_answer
                mock_rdata = MagicMock()
                mock_rdata.__str__ = lambda self: '"v=spf1 include:example.com ~all"'
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer
            if rdtype == "CNAME":
                # www CNAME
                mock_rdata = MagicMock()
                mock_rdata.__str__ = lambda self: "example.com."
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer

            import dns.resolver
            raise dns.resolver.NoAnswer()

        with patch("app.services.domain.dns.resolver.Resolver") as mock_resolver_cls:
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_resolver_cls.return_value = mock_resolver

            result = await service._check_dns("example.com")

        assert result.has_a_record is True
        assert result.has_aaaa_record is True
        assert result.has_mx_record is True
        assert result.has_ns_record is True
        assert result.has_spf is True
        assert result.has_dmarc is True
        assert result.www_resolves is True
        assert result.cloudflare_detected is False
        assert result.cloudflare_proxied is False
        assert result.status == DomainCheckStatus.PASS

    @pytest.mark.asyncio
    async def test_dns_cloudflare_detected(self, service: DomainSecurityService):
        """Cloudflare NS + Cloudflare IPs should set both flags."""
        def fake_resolve(qname, rdtype):
            mock_answer = MagicMock()
            mock_rrset = MagicMock()
            mock_rrset.ttl = 300
            mock_answer.rrset = mock_rrset

            if rdtype == "NS":
                ns1 = MagicMock()
                ns1.__str__ = lambda self: "anna.ns.cloudflare.com."
                ns2 = MagicMock()
                ns2.__str__ = lambda self: "bob.ns.cloudflare.com."
                mock_answer.__iter__ = lambda self: iter([ns1, ns2])
                return mock_answer
            if rdtype == "A":
                mock_rdata = MagicMock()
                mock_rdata.__str__ = lambda self: "104.21.50.123"
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer

            import dns.resolver
            raise dns.resolver.NoAnswer()

        with patch("app.services.domain.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_cls.return_value = mock_resolver

            result = await service._check_dns("cloudflare-site.com")

        assert result.cloudflare_detected is True
        assert result.cloudflare_proxied is True
        assert result.has_a_record is True

    @pytest.mark.asyncio
    async def test_dns_cloudflare_ns_non_proxied(self, service: DomainSecurityService):
        """Cloudflare NS but non-Cloudflare IPs → detected but not proxied."""
        def fake_resolve(qname, rdtype):
            mock_answer = MagicMock()
            mock_rrset = MagicMock()
            mock_rrset.ttl = 300
            mock_answer.rrset = mock_rrset

            if rdtype == "NS":
                ns1 = MagicMock()
                ns1.__str__ = lambda self: "anna.ns.cloudflare.com."
                mock_answer.__iter__ = lambda self: iter([ns1])
                return mock_answer
            if rdtype == "A":
                mock_rdata = MagicMock()
                # Non-Cloudflare IP (DNS-only mode / grey cloud)
                mock_rdata.__str__ = lambda self: "1.2.3.4"
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                return mock_answer

            import dns.resolver
            raise dns.resolver.NoAnswer()

        with patch("app.services.domain.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_cls.return_value = mock_resolver

            result = await service._check_dns("cf-dns-only.com")

        assert result.cloudflare_detected is True
        assert result.cloudflare_proxied is False

    @pytest.mark.asyncio
    async def test_dns_check_error(self, service: DomainSecurityService):
        with patch(
            "app.services.domain.dns.resolver.Resolver",
            side_effect=Exception("DNS error"),
        ):
            result = await service._check_dns("bad.example.com")

        assert result.status == DomainCheckStatus.ERROR
        assert "DNS error" in result.error


# ------------------------------------------------------------------
# DNSSEC check
# ------------------------------------------------------------------

class TestDnssecCheck:
    @pytest.mark.asyncio
    async def test_dnssec_via_ad_flag_cloudflare(self, service: DomainSecurityService):
        """DNSSEC detected via AD flag from validating resolver (Cloudflare-style)."""
        import dns.resolver as dns_resolver

        def fake_resolve(qname, rdtype):
            mock_answer = MagicMock()
            if rdtype == "NS":
                ns = MagicMock()
                ns.__str__ = lambda self: "anna.ns.cloudflare.com."
                mock_answer.__iter__ = lambda self: iter([ns])
                return mock_answer
            if rdtype == "A":
                a_rdata = MagicMock()
                a_rdata.__str__ = lambda self: "172.64.0.1"
                mock_answer.__iter__ = lambda self: iter([a_rdata])
                return mock_answer
            if rdtype == "DS":
                ds_rdata = MagicMock()
                mock_answer.__iter__ = lambda self: iter([ds_rdata])
                return mock_answer
            raise dns_resolver.NoAnswer()

        # Mock the authoritative DNSKEY query
        mock_dnskey_rrset = MagicMock()
        mock_dnskey_rdata = MagicMock()
        mock_dnskey_rdata.algorithm = 13
        mock_dnskey_rrset.__iter__ = lambda self: iter([mock_dnskey_rdata])

        with (
            patch.object(
                service, "_query_validating_resolver",
                return_value=(True, True, "salut-fred.fr", "ECDSA/P-256/SHA-256"),
            ),
            patch("app.services.domain.dns.resolver.Resolver") as mock_cls,
            patch.object(
                service, "_query_with_dnssec",
                return_value=mock_dnskey_rrset,
            ),
        ):
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_cls.return_value = mock_resolver

            result = await service._check_dnssec("salut-fred.fr")

        assert result.enabled is True
        assert result.ad_flag is True
        assert result.has_rrsig is True
        assert result.rrsig_signer == "salut-fred.fr"
        assert result.has_dnskey is True
        assert result.ds_records_found is True
        assert result.status == DomainCheckStatus.PASS
        assert "ECDSA" in result.algorithm
        assert result.validation_method == "ad_flag"

    @pytest.mark.asyncio
    async def test_dnssec_via_rrsig_only(self, service: DomainSecurityService):
        """DNSSEC detected via RRSIG without AD flag (some resolvers strip AD)."""
        import dns.resolver as dns_resolver

        def fake_resolve(qname, rdtype):
            raise dns_resolver.NoAnswer()

        with (
            patch.object(
                service, "_query_validating_resolver",
                return_value=(False, True, "example.com", "RSA/SHA-256"),
            ),
            patch("app.services.domain.dns.resolver.Resolver") as mock_cls,
        ):
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_cls.return_value = mock_resolver

            result = await service._check_dnssec("example.com")

        assert result.enabled is True
        assert result.ad_flag is False
        assert result.has_rrsig is True
        assert result.status == DomainCheckStatus.PASS
        assert result.validation_method == "rrsig"

    @pytest.mark.asyncio
    async def test_dnssec_fallback_dnskey_and_ds(self, service: DomainSecurityService):
        """DNSSEC detected via DNSKEY+DS when validating resolver is unreachable."""
        import dns.resolver as dns_resolver

        def fake_resolve(qname, rdtype):
            mock_answer = MagicMock()
            if rdtype == "NS":
                raise dns_resolver.NoAnswer()
            if rdtype == "DNSKEY":
                rdata = MagicMock()
                rdata.algorithm = 8
                mock_answer.__iter__ = lambda self: iter([rdata])
                return mock_answer
            if rdtype == "DS":
                ds_rdata = MagicMock()
                mock_answer.__iter__ = lambda self: iter([ds_rdata])
                return mock_answer
            raise dns_resolver.NoAnswer()

        with (
            patch.object(
                service, "_query_validating_resolver",
                side_effect=Exception("Network unreachable"),
            ),
            patch("app.services.domain.dns.resolver.Resolver") as mock_cls,
        ):
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_cls.return_value = mock_resolver

            result = await service._check_dnssec("example.com")

        assert result.enabled is True
        assert result.has_dnskey is True
        assert result.ds_records_found is True
        assert result.status == DomainCheckStatus.PASS
        assert "RSA/SHA-256" in result.algorithm
        assert result.validation_method == "dnskey"

    @pytest.mark.asyncio
    async def test_dnssec_warning_partial_evidence(self, service: DomainSecurityService):
        """Only DNSKEY without DS → warning status."""
        import dns.resolver as dns_resolver

        def fake_resolve(qname, rdtype):
            mock_answer = MagicMock()
            if rdtype == "DNSKEY":
                rdata = MagicMock()
                rdata.algorithm = 13
                mock_answer.__iter__ = lambda self: iter([rdata])
                return mock_answer
            raise dns_resolver.NoAnswer()

        with (
            patch.object(
                service, "_query_validating_resolver",
                return_value=(False, False, "", ""),
            ),
            patch("app.services.domain.dns.resolver.Resolver") as mock_cls,
        ):
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_cls.return_value = mock_resolver

            result = await service._check_dnssec("partial.com")

        # DNSKEY without DS → not fully enabled but has partial evidence
        assert result.enabled is False
        assert result.has_dnskey is True
        assert result.ds_records_found is False
        assert result.status == DomainCheckStatus.WARNING

    @pytest.mark.asyncio
    async def test_dnssec_disabled(self, service: DomainSecurityService):
        """No DNSSEC signals at all → fail."""
        import dns.resolver as dns_resolver

        def fake_resolve(qname, rdtype):
            raise dns_resolver.NoAnswer()

        with (
            patch.object(
                service, "_query_validating_resolver",
                return_value=(False, False, "", ""),
            ),
            patch("app.services.domain.dns.resolver.Resolver") as mock_cls,
        ):
            mock_resolver = MagicMock()
            mock_resolver.resolve = fake_resolve
            mock_cls.return_value = mock_resolver

            result = await service._check_dnssec("no-dnssec.com")

        assert result.enabled is False
        assert result.ad_flag is False
        assert result.has_rrsig is False
        assert result.has_dnskey is False
        assert result.ds_records_found is False
        assert result.status == DomainCheckStatus.FAIL
        assert result.validation_method == ""

    @pytest.mark.asyncio
    async def test_dnssec_check_error(self, service: DomainSecurityService):
        """Complete failure of DNSSEC check → error status."""
        with (
            patch.object(
                service, "_query_validating_resolver",
                side_effect=Exception("Network error"),
            ),
            patch(
                "app.services.domain.dns.resolver.Resolver",
                side_effect=Exception("Fatal resolver error"),
            ),
        ):
            result = await service._check_dnssec("broken.com")

        assert result.status == DomainCheckStatus.ERROR
        assert result.error != ""


class TestQueryValidatingResolver:
    def test_ad_flag_and_rrsig_detected(self, service: DomainSecurityService):
        """Simulate a response with AD flag set and RRSIG present."""
        import dns.flags as dnsflags

        mock_response = MagicMock()
        mock_response.flags = dnsflags.QR | dnsflags.RD | dnsflags.RA | dnsflags.AD

        # A record RRset
        a_rrset = MagicMock()
        a_rrset.rdtype = dns.rdatatype.from_text("A")

        # RRSIG RRset
        rrsig_rrset = MagicMock()
        rrsig_rrset.rdtype = dns.rdatatype.from_text("RRSIG")
        rrsig_rdata = MagicMock()
        rrsig_rdata.signer = MagicMock()
        rrsig_rdata.signer.__str__ = lambda self: "salut-fred.fr."
        rrsig_rdata.algorithm = 13
        rrsig_rrset.__iter__ = lambda self: iter([rrsig_rdata])

        mock_response.answer = [a_rrset, rrsig_rrset]

        with (
            patch("app.services.domain.dns.message.make_query"),
            patch("app.services.domain.dns.query.udp", return_value=mock_response),
        ):
            ad, rrsig, signer, algo = service._query_validating_resolver(
                "salut-fred.fr", "1.1.1.1",
            )

        assert ad is True
        assert rrsig is True
        assert signer == "salut-fred.fr"
        assert "ECDSA" in algo

    def test_no_ad_no_rrsig(self, service: DomainSecurityService):
        """Response without AD flag or RRSIG → both False."""
        mock_response = MagicMock()
        mock_response.flags = 0  # No AD flag

        # A record only, no RRSIG
        a_rrset = MagicMock()
        a_rrset.rdtype = dns.rdatatype.from_text("A")
        mock_response.answer = [a_rrset]

        with (
            patch("app.services.domain.dns.message.make_query"),
            patch("app.services.domain.dns.query.udp", return_value=mock_response),
        ):
            ad, rrsig, signer, algo = service._query_validating_resolver(
                "no-dnssec.com", "1.1.1.1",
            )

        assert ad is False
        assert rrsig is False
        assert signer == ""
        assert algo == ""


class TestPickValidationMethod:
    def test_ad_flag_priority(self, service: DomainSecurityService):
        assert service._pick_validation_method(True, True, True, True) == "ad_flag"

    def test_rrsig_priority(self, service: DomainSecurityService):
        assert service._pick_validation_method(False, True, True, True) == "rrsig"

    def test_dnskey_priority(self, service: DomainSecurityService):
        assert service._pick_validation_method(False, False, True, True) == "dnskey"

    def test_ds_only(self, service: DomainSecurityService):
        assert service._pick_validation_method(False, False, False, True) == "ds"

    def test_nothing(self, service: DomainSecurityService):
        assert service._pick_validation_method(False, False, False, False) == ""


# ------------------------------------------------------------------
# check_all orchestration
# ------------------------------------------------------------------

class TestCheckAll:
    @pytest.mark.asyncio
    async def test_check_all_aggregates_results(self, service: DomainSecurityService):
        """Verify check_all runs all checks and builds a summary."""
        from app.models.domain import (
            DnsInfo,
            DnssecInfo,
            HstsInfo,
            SslInfo,
            WhoisInfo,
        )

        with (
            patch.object(
                service, "_check_whois",
                return_value=WhoisInfo(status=DomainCheckStatus.PASS),
            ),
            patch.object(
                service, "_check_dns",
                return_value=DnsInfo(status=DomainCheckStatus.PASS),
            ),
            patch.object(
                service, "_check_ssl",
                return_value=SslInfo(status=DomainCheckStatus.WARNING),
            ),
            patch.object(
                service, "_check_hsts",
                return_value=HstsInfo(status=DomainCheckStatus.FAIL),
            ),
            patch.object(
                service, "_check_dnssec",
                return_value=DnssecInfo(status=DomainCheckStatus.PASS),
            ),
        ):
            report = await service.check_all("example.com")

        assert report.domain == "example.com"
        assert report.checks_summary.total == 5
        assert report.checks_summary.passed == 3
        assert report.checks_summary.warnings == 1
        assert report.checks_summary.failed == 1

    @pytest.mark.asyncio
    async def test_check_all_handles_individual_failures(self, service: DomainSecurityService):
        """One check erroring should not prevent others from completing."""
        from app.models.domain import (
            DnsInfo,
            DnssecInfo,
            HstsInfo,
            SslInfo,
            WhoisInfo,
        )

        with (
            patch.object(
                service, "_check_whois",
                return_value=WhoisInfo(status=DomainCheckStatus.ERROR, error="timeout"),
            ),
            patch.object(
                service, "_check_dns",
                return_value=DnsInfo(status=DomainCheckStatus.PASS),
            ),
            patch.object(
                service, "_check_ssl",
                return_value=SslInfo(status=DomainCheckStatus.PASS),
            ),
            patch.object(
                service, "_check_hsts",
                return_value=HstsInfo(status=DomainCheckStatus.PASS),
            ),
            patch.object(
                service, "_check_dnssec",
                return_value=DnssecInfo(status=DomainCheckStatus.PASS),
            ),
        ):
            report = await service.check_all("example.com")

        assert report.checks_summary.errors == 1
        assert report.checks_summary.passed == 4


# ------------------------------------------------------------------
# Privacy detection
# ------------------------------------------------------------------

class TestPrivacyDetection:
    def test_detects_redacted(self, service: DomainSecurityService):
        assert service._detect_privacy("REDACTED FOR PRIVACY", "", "") is True

    def test_detects_whoisguard(self, service: DomainSecurityService):
        assert service._detect_privacy("", "WhoisGuard, Inc.", "") is True

    def test_detects_domains_by_proxy(self, service: DomainSecurityService):
        assert service._detect_privacy("", "Domains By Proxy, LLC", "") is True

    def test_no_privacy(self, service: DomainSecurityService):
        assert service._detect_privacy("John Doe", "ACME Corp", "GoDaddy") is False


# ------------------------------------------------------------------
# DNSSEC algorithm names
# ------------------------------------------------------------------

class TestDnssecAlgorithmName:
    def test_known_algorithm(self, service: DomainSecurityService):
        assert service._dnssec_algorithm_name(13) == "ECDSA/P-256/SHA-256"
        assert service._dnssec_algorithm_name(8) == "RSA/SHA-256"

    def test_unknown_algorithm(self, service: DomainSecurityService):
        assert service._dnssec_algorithm_name(99) == "Algorithm-99"


# ------------------------------------------------------------------
# Cloudflare detection helpers
# ------------------------------------------------------------------

class TestCloudflareDetection:
    def test_cloudflare_ns_detected(self, service: DomainSecurityService):
        ns_values = ["anna.ns.cloudflare.com.", "bob.ns.cloudflare.com."]
        assert service._detect_cloudflare_ns(ns_values) is True

    def test_non_cloudflare_ns(self, service: DomainSecurityService):
        ns_values = ["ns1.example.com.", "ns2.example.com."]
        assert service._detect_cloudflare_ns(ns_values) is False

    def test_cloudflare_ips(self, service: DomainSecurityService):
        ips = ["104.21.50.123"]
        assert service._detect_cloudflare_ips(ips) is True

    def test_cloudflare_ips_172(self, service: DomainSecurityService):
        ips = ["172.67.1.2"]
        assert service._detect_cloudflare_ips(ips) is True

    def test_non_cloudflare_ips(self, service: DomainSecurityService):
        ips = ["93.184.216.34", "1.2.3.4"]
        assert service._detect_cloudflare_ips(ips) is False

    def test_empty_lists(self, service: DomainSecurityService):
        assert service._detect_cloudflare_ns([]) is False
        assert service._detect_cloudflare_ips([]) is False
