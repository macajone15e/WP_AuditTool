"""Domain security verification service.

Checks WHOIS, DNS records, SSL certificates, HSTS headers, and DNSSEC.
"""

import asyncio
import contextlib
import ipaddress
import logging
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import httpx
import whois

from app.constants import WHOIS_PRIVACY_PATTERNS, DomainCheckStatus
from app.models.domain import (
    ChecksSummary,
    DnsInfo,
    DnsRecord,
    DnssecInfo,
    DomainSecurityReport,
    HstsInfo,
    SslInfo,
    WhoisInfo,
)

logger = logging.getLogger(__name__)

# Minimum acceptable days before domain/cert expiry.
_DOMAIN_EXPIRY_WARNING_DAYS = 30
_CERT_EXPIRY_WARNING_DAYS = 14

# Cloudflare detection patterns.
_CLOUDFLARE_NS_SUFFIX = ".ns.cloudflare.com."
# Cloudflare IPv4 ranges
_CLOUDFLARE_IPV4_NETWORKS = (
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
)

# Public DNSSEC-validating resolvers used for AD flag verification.
# ISP/local resolvers often strip the AD flag, so we query these directly.
_DNSSEC_RESOLVERS = ("1.1.1.1", "8.8.8.8")


class DomainSecurityService:
    """Run domain-level security checks.

    All checks are executed concurrently and errors in one check do not
    prevent others from completing.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check_all(self, domain: str) -> DomainSecurityReport:
        """Run every domain security check and return an aggregated report.

        Args:
            domain: Bare domain name (e.g. ``"example.com"``).

        Returns:
            Fully populated ``DomainSecurityReport``.

        """
        logger.info("Starting domain security audit for %s", domain)

        whois_info, dns_info, ssl_info, hsts_info, dnssec_info = (
            await asyncio.gather(
                self._check_whois(domain),
                self._check_dns(domain),
                self._check_ssl(domain),
                self._check_hsts(domain),
                self._check_dnssec(domain),
            )
        )

        summary = self._compute_summary(
            whois_info, dns_info, ssl_info, hsts_info, dnssec_info,
        )

        logger.info(
            "Domain audit complete for %s — %d passed, %d warnings, %d failed",
            domain,
            summary.passed,
            summary.warnings,
            summary.failed,
        )

        return DomainSecurityReport(
            domain=domain,
            scan_time=datetime.now(tz=UTC).isoformat(),
            whois=whois_info,
            dns=dns_info,
            ssl=ssl_info,
            hsts=hsts_info,
            dnssec=dnssec_info,
            checks_summary=summary,
        )

    # ------------------------------------------------------------------
    # Domain extraction helper
    # ------------------------------------------------------------------

    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract the bare domain from a URL.

        Args:
            url: Full URL or bare domain.

        Returns:
            Bare domain name without ``www.`` prefix.

        """
        if "://" in url:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        else:
            host = url.split("/")[0].split(":")[0]

        host = host.lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        return host

    # ------------------------------------------------------------------
    # WHOIS check
    # ------------------------------------------------------------------

    async def _check_whois(self, domain: str) -> WhoisInfo:
        """Query WHOIS data for *domain*."""
        try:
            data = await asyncio.to_thread(whois.whois, domain)
        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
            return WhoisInfo(
                status=DomainCheckStatus.ERROR,
                reason=f"WHOIS lookup failed: {exc}",
                error=str(exc),
            )

        return self._parse_whois(data, domain)

    def _parse_whois(self, data: whois.WhoisEntry, domain: str) -> WhoisInfo:
        """Parse a whois.WhoisEntry into a WhoisInfo model."""
        creation = self._extract_date(data.get("creation_date"))
        expiration = self._extract_date(data.get("expiration_date"))

        days_until_expiry = None
        if expiration:
            delta = expiration - datetime.now(tz=UTC)
            days_until_expiry = delta.days

        status_raw = data.get("status", [])
        if isinstance(status_raw, str):
            status_raw = [status_raw]
        status_codes = [s.split()[0] if " " in s else s for s in status_raw]

        transfer_locked = any(
            "clienttransferprohibited" in s.lower() for s in status_codes
        )

        registrant_name = str(data.get("name", "") or "")
        registrant_org = str(data.get("org", "") or "")
        registrar = str(data.get("registrar", "") or "")
        privacy_enabled = self._detect_privacy(
            registrant_name, registrant_org, registrar,
        )

        name_servers_raw = data.get("name_servers", [])
        if isinstance(name_servers_raw, str):
            name_servers_raw = [name_servers_raw]
        name_servers = sorted({ns.lower().rstrip(".") for ns in name_servers_raw if ns})

        # Determine overall status and reason
        check_status = DomainCheckStatus.PASS
        reason_parts: list[str] = []
        if days_until_expiry is not None and days_until_expiry < 0:
            check_status = DomainCheckStatus.FAIL
            reason_parts.append(f"Domain expired {abs(days_until_expiry)} days ago")
        elif days_until_expiry is not None and days_until_expiry < _DOMAIN_EXPIRY_WARNING_DAYS:
            check_status = DomainCheckStatus.WARNING
            reason_parts.append(
                f"Domain expires in {days_until_expiry} days "
                f"(threshold: {_DOMAIN_EXPIRY_WARNING_DAYS}d)",
            )
        if not transfer_locked:
            if check_status == DomainCheckStatus.PASS:
                check_status = DomainCheckStatus.WARNING
            reason_parts.append(
                "Transfer lock (clientTransferProhibited) is not enabled",
            )

        return WhoisInfo(
            status=check_status,
            registrar=registrar,
            creation_date=creation.isoformat() if creation else "",
            expiration_date=expiration.isoformat() if expiration else "",
            days_until_expiry=days_until_expiry,
            transfer_locked=transfer_locked,
            privacy_enabled=privacy_enabled,
            whois_status_codes=status_codes,
            registrant_name=registrant_name,
            registrant_org=registrant_org,
            name_servers=name_servers,
            reason=" · ".join(reason_parts),
        )

    @staticmethod
    def _extract_date(value: object) -> datetime | None:
        """Extract a single datetime from a WHOIS date field.

        The field may be a single datetime, a list of datetimes, or ``None``.
        """
        if value is None:
            return None
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value
        return None

    @staticmethod
    def _detect_privacy(name: str, org: str, registrar: str) -> bool:
        """Return ``True`` if any field suggests a privacy/proxy service."""
        combined = f"{name} {org} {registrar}".lower()
        return any(pattern in combined for pattern in WHOIS_PRIVACY_PATTERNS)

    # ------------------------------------------------------------------
    # DNS check
    # ------------------------------------------------------------------

    async def _check_dns(self, domain: str) -> DnsInfo:
        """Resolve DNS records for *domain*."""
        try:
            return await asyncio.to_thread(self._resolve_dns, domain)
        except Exception as exc:
            logger.warning("DNS check failed for %s: %s", domain, exc)
            return DnsInfo(
                status=DomainCheckStatus.ERROR,
                reason=f"DNS resolution failed: {exc}",
                error=str(exc),
            )

    def _resolve_dns(self, domain: str) -> DnsInfo:
        """Resolve all DNS record types for *domain* synchronously."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        records: list[DnsRecord] = []
        has_a = has_aaaa = has_mx = has_ns = has_spf = has_dmarc = False
        ns_values: list[str] = []

        # NS records (resolve first for Cloudflare detection)
        for rdata, ttl in self._safe_resolve(resolver, domain, "NS"):
            ns_value = str(rdata)
            ns_values.append(ns_value)
            records.append(DnsRecord(
                record_type="NS", name=domain, value=ns_value, ttl=ttl,
            ))
            has_ns = True

        # Detect Cloudflare from nameservers
        cloudflare_ns = self._detect_cloudflare_ns(ns_values)

        # A records
        a_values: list[str] = []
        for rdata, ttl in self._safe_resolve(resolver, domain, "A"):
            ip_value = str(rdata)
            a_values.append(ip_value)
            records.append(DnsRecord(
                record_type="A", name=domain, value=ip_value, ttl=ttl,
            ))
            has_a = True

        # AAAA records
        for rdata, ttl in self._safe_resolve(resolver, domain, "AAAA"):
            records.append(DnsRecord(
                record_type="AAAA", name=domain, value=str(rdata), ttl=ttl,
            ))
            has_aaaa = True

        # Detect Cloudflare proxy from IPs
        cloudflare_proxied = cloudflare_ns and self._detect_cloudflare_ips(a_values)

        # MX records
        for rdata, ttl in self._safe_resolve(resolver, domain, "MX"):
            records.append(DnsRecord(
                record_type="MX", name=domain, value=str(rdata), ttl=ttl,
            ))
            has_mx = True

        # TXT records (including SPF and DMARC)
        for rdata, ttl in self._safe_resolve(resolver, domain, "TXT"):
            txt_value = str(rdata).strip('"')
            records.append(DnsRecord(
                record_type="TXT", name=domain, value=txt_value, ttl=ttl,
            ))
            if txt_value.lower().startswith("v=spf1"):
                has_spf = True

        # DMARC (TXT at _dmarc.domain)
        for rdata, ttl in self._safe_resolve(resolver, f"_dmarc.{domain}", "TXT"):
            txt_value = str(rdata).strip('"')
            records.append(DnsRecord(
                record_type="TXT", name=f"_dmarc.{domain}", value=txt_value, ttl=ttl,
            ))
            if "v=dmarc1" in txt_value.lower():
                has_dmarc = True

        # www check
        www_resolves, www_target = self._check_www(resolver, domain)
        if www_target:
            try:
                ip_addr = ipaddress.ip_address(www_target)
                if any(ip_addr in net for net in _CLOUDFLARE_IPV4_NETWORKS):
                    www_target = "☁️ Cloudflare proxy"
            except ValueError:
                pass

        # Determine status and reason
        check_status = DomainCheckStatus.PASS
        reason_parts: list[str] = []
        if not has_a and not has_aaaa:
            check_status = DomainCheckStatus.FAIL
            reason_parts.append("No A or AAAA record found — domain does not resolve")
        else:
            missing_mail: list[str] = []
            if not has_mx:
                missing_mail.append("MX")
            if not has_spf:
                missing_mail.append("SPF")
            if not has_dmarc:
                missing_mail.append("DMARC")
            if missing_mail:
                check_status = DomainCheckStatus.WARNING
                reason_parts.append(
                    f"Missing email security records: {', '.join(missing_mail)}",
                )

        if cloudflare_proxied:
            logger.info(
                "Cloudflare proxy detected for %s — A/AAAA are proxy IPs",
                domain,
            )

        return DnsInfo(
            status=check_status,
            records=records,
            has_a_record=has_a,
            has_aaaa_record=has_aaaa,
            has_mx_record=has_mx,
            has_ns_record=has_ns,
            has_spf=has_spf,
            has_dmarc=has_dmarc,
            www_resolves=www_resolves,
            www_redirects_correctly=www_resolves,
            www_target=www_target,
            cloudflare_detected=cloudflare_ns,
            cloudflare_proxied=cloudflare_proxied,
            reason=" · ".join(reason_parts),
        )

    @staticmethod
    def _safe_resolve(
        resolver: dns.resolver.Resolver,
        qname: str,
        rdtype: str,
    ) -> list[tuple[object, int]]:
        """Resolve without raising if the record does not exist."""
        try:
            answer = resolver.resolve(qname, rdtype)
            return [(rdata, answer.rrset.ttl) for rdata in answer]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.name.EmptyLabel,
        ):
            return []

    @staticmethod
    def _check_www(
        resolver: dns.resolver.Resolver,
        domain: str,
    ) -> tuple[bool, str]:
        """Check if ``www.<domain>`` resolves."""
        www = f"www.{domain}"
        try:
            # Try CNAME first
            answer = resolver.resolve(www, "CNAME")
            target = str(next(iter(answer))).rstrip(".")
            return True, target
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.name.EmptyLabel,
        ):
            pass

        try:
            answer = resolver.resolve(www, "A")
            target = str(next(iter(answer)))
            return True, target
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.name.EmptyLabel,
        ):
            return False, ""

    @staticmethod
    def _detect_cloudflare_ns(ns_values: list[str]) -> bool:
        """Return ``True`` if any NS record points to a Cloudflare nameserver."""
        return any(
            ns.lower().rstrip(".").endswith(".ns.cloudflare.com")
            for ns in ns_values
        )

    @staticmethod
    def _detect_cloudflare_ips(ip_values: list[str]) -> bool:
        """Return ``True`` if any IP belongs to a known Cloudflare range."""
        for ip_str in ip_values:
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                if any(ip_addr in net for net in _CLOUDFLARE_IPV4_NETWORKS):
                    return True
            except ValueError:
                pass
        return False

    # ------------------------------------------------------------------
    # SSL check
    # ------------------------------------------------------------------

    async def _check_ssl(self, domain: str) -> SslInfo:
        """Verify the SSL/TLS certificate for *domain*."""
        try:
            return await asyncio.to_thread(self._verify_ssl, domain)
        except Exception as exc:
            logger.warning("SSL check failed for %s: %s", domain, exc)
            return SslInfo(
                status=DomainCheckStatus.FAIL,
                reason=f"SSL connection failed: {exc}",
                error=str(exc),
            )

    def _verify_ssl(self, domain: str) -> SslInfo:
        """Verify the SSL/TLS certificate for *domain* synchronously."""
        context = ssl.create_default_context()

        try:
            with (
                socket.create_connection((domain, 443), timeout=10) as sock,
                context.wrap_socket(sock, server_hostname=domain) as ssock,
            ):
                cert = ssock.getpeercert()
                protocol = ssock.version() or ""
        except ssl.SSLCertVerificationError as exc:
            return SslInfo(
                status=DomainCheckStatus.FAIL,
                is_valid=False,
                reason=f"Certificate verification failed: {exc}",
                error=f"Certificate verification failed: {exc}",
            )
        except (OSError, TimeoutError) as exc:
            return SslInfo(
                status=DomainCheckStatus.FAIL,
                reason=f"Could not connect on port 443: {exc}",
                error=f"Connection failed: {exc}",
            )

        if not cert:
            return SslInfo(
                status=DomainCheckStatus.FAIL,
                reason="Server did not return an SSL certificate",
                error="No certificate returned",
            )

        return self._parse_certificate(cert, protocol)

    def _parse_certificate(self, cert: dict, protocol: str) -> SslInfo:
        """Extract information from a certificate dict."""
        # Issuer
        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_type, attr_value in rdn:
                if attr_type == "organizationName":
                    issuer_parts.append(attr_value)
        issuer = ", ".join(issuer_parts) or "Unknown"

        # Subject CN
        subject = ""
        for rdn in cert.get("subject", ()):
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    subject = attr_value

        # SAN
        san = [
            value
            for san_type, value in cert.get("subjectAltName", ())
            if san_type == "DNS"
        ]

        # Dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        valid_from = self._parse_ssl_date(not_before)
        valid_to = self._parse_ssl_date(not_after)

        days_until_expiry = None
        if valid_to:
            delta = valid_to - datetime.now(tz=UTC)
            days_until_expiry = delta.days

        # Status and reason
        is_valid = True
        check_status = DomainCheckStatus.PASS
        reason = ""
        if days_until_expiry is not None and days_until_expiry < 0:
            check_status = DomainCheckStatus.FAIL
            is_valid = False
            reason = f"SSL certificate expired {abs(days_until_expiry)} days ago"
        elif days_until_expiry is not None and days_until_expiry < _CERT_EXPIRY_WARNING_DAYS:
            check_status = DomainCheckStatus.WARNING
            reason = (
                f"SSL certificate expires in {days_until_expiry} days "
                f"(threshold: {_CERT_EXPIRY_WARNING_DAYS}d)"
            )

        return SslInfo(
            status=check_status,
            issuer=issuer,
            subject=subject,
            san=san,
            valid_from=valid_from.isoformat() if valid_from else not_before,
            valid_to=valid_to.isoformat() if valid_to else not_after,
            days_until_expiry=days_until_expiry,
            protocol_version=protocol,
            is_valid=is_valid,
            reason=reason,
        )

    @staticmethod
    def _parse_ssl_date(date_str: str) -> datetime | None:
        """Parse an SSL certificate date string."""
        if not date_str:
            return None
        try:
            # Format: 'Mon DD HH:MM:SS YYYY GMT'
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=UTC)
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # HSTS check
    # ------------------------------------------------------------------

    async def _check_hsts(self, domain: str) -> HstsInfo:
        """Check for the Strict-Transport-Security header on *domain*."""
        url = f"https://{domain}"
        try:
            async with httpx.AsyncClient(
                timeout=10,
                follow_redirects=True,
                verify=False,  # We only care about the HSTS header, not the cert
            ) as client:
                response = await client.head(url)
                hsts_header = response.headers.get("strict-transport-security", "")
        except Exception as exc:
            logger.warning("HSTS check failed for %s: %s", domain, exc)
            return HstsInfo(
                status=DomainCheckStatus.ERROR,
                reason=f"Could not check HSTS header: {exc}",
                error=str(exc),
            )

        if not hsts_header:
            return HstsInfo(
                status=DomainCheckStatus.FAIL,
                enabled=False,
                reason="Strict-Transport-Security header is missing",
            )

        return self._parse_hsts(hsts_header)

    @staticmethod
    def _parse_hsts(header: str) -> HstsInfo:
        """Parse a Strict-Transport-Security header value."""
        directives = [d.strip().lower() for d in header.split(";")]

        max_age: int | None = None
        include_subdomains = False
        preload = False

        for directive in directives:
            if directive.startswith("max-age="):
                with contextlib.suppress(ValueError):
                    max_age = int(directive.split("=", 1)[1])
            elif directive == "includesubdomains":
                include_subdomains = True
            elif directive == "preload":
                preload = True

        # Status logic and reason
        check_status = DomainCheckStatus.PASS
        reason = ""
        if max_age is not None and max_age < 15552000:  # Less than 6 months (180 days)
            check_status = DomainCheckStatus.WARNING
            reason = (
                f"HSTS max-age is {max_age}s "
                f"(recommended: ≥ 15552000s / 6 months)"
            )

        return HstsInfo(
            status=check_status,
            enabled=True,
            max_age=max_age,
            include_subdomains=include_subdomains,
            preload=preload,
            raw_header=header,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # DNSSEC check
    # ------------------------------------------------------------------

    async def _check_dnssec(self, domain: str) -> DnssecInfo:
        """Check DNSSEC status for *domain*."""
        try:
            return await asyncio.to_thread(self._verify_dnssec, domain)
        except Exception as exc:
            logger.warning("DNSSEC check failed for %s: %s", domain, exc)
            return DnssecInfo(
                status=DomainCheckStatus.ERROR,
                reason=f"DNSSEC verification failed: {exc}",
                error=str(exc),
            )

    def _verify_dnssec(self, domain: str) -> DnssecInfo:
        """Verify DNSSEC for *domain* using a rigorous multi-layer approach.

        Strategy
        --------
        1. **AD flag + RRSIG** — Send an A query with the DO (DNSSEC OK) flag
           to public validating resolvers (1.1.1.1, 8.8.8.8).  If the AD flag
           is set in the response, the entire chain of trust was validated.
           At the same time, look for RRSIG records in the answer section to
           extract the signing algorithm and signer name.
        2. **DNSKEY via authoritative NS** — Query the domain's own
           nameservers directly for DNSKEY records (with DO flag).
        3. **DNSKEY via recursive resolver** — Fall back to the system
           resolver for DNSKEY if the direct query failed.
        4. **DS at parent** — Check for DS records at the parent zone.

        Any *one* of these signals being positive is enough to conclude
        DNSSEC is enabled.
        """
        # --- Step 1: AD flag + RRSIG via validating resolvers --------
        ad_flag = False
        has_rrsig = False
        rrsig_signer = ""
        rrsig_algorithm = ""

        for resolver_ip in _DNSSEC_RESOLVERS:
            try:
                ad, rrsig, signer, algo = self._query_validating_resolver(
                    domain, resolver_ip,
                )
                if ad:
                    ad_flag = True
                if rrsig:
                    has_rrsig = True
                    rrsig_signer = rrsig_signer or signer
                    rrsig_algorithm = rrsig_algorithm or algo
                if ad_flag and has_rrsig:
                    break  # Both confirmed, no need to try the next resolver.
            except Exception:
                logger.debug(
                    "Validating resolver %s failed for %s",
                    resolver_ip, domain, exc_info=True,
                )
                continue

        # --- Step 2: DNSKEY via authoritative NS ---------------------
        has_dnskey = False
        dnskey_algorithm = ""

        helper_resolver = dns.resolver.Resolver()
        helper_resolver.timeout = 5
        helper_resolver.lifetime = 10

        auth_ips = self._find_authoritative_ns_ips(helper_resolver, domain)
        for ns_ip in auth_ips:
            try:
                dnskey_result = self._query_with_dnssec(
                    domain, "DNSKEY", ns_ip,
                )
                if dnskey_result:
                    has_dnskey = True
                    for rdata in dnskey_result:
                        algo_num = getattr(rdata, "algorithm", None)
                        if algo_num is not None:
                            dnskey_algorithm = self._dnssec_algorithm_name(
                                algo_num,
                            )
                        break
                    break  # One successful NS is enough.
            except Exception:
                continue

        # --- Step 3: DNSKEY via recursive resolver fallback ----------
        if not has_dnskey:
            try:
                answer = helper_resolver.resolve(domain, "DNSKEY")
                has_dnskey = True
                for rdata in answer:
                    algo_num = getattr(rdata, "algorithm", None)
                    if algo_num is not None:
                        dnskey_algorithm = self._dnssec_algorithm_name(
                            algo_num,
                        )
                    break
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.resolver.Timeout,
            ):
                pass

        # --- Step 4: DS records at parent zone -----------------------
        has_ds = False
        try:
            helper_resolver.resolve(domain, "DS")
            has_ds = True
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
        ):
            pass

        # --- Aggregate results ---------------------------------------
        # Pick the best algorithm string available.
        algorithm = rrsig_algorithm or dnskey_algorithm

        # Determine the primary detection method.
        validation_method = self._pick_validation_method(
            ad_flag, has_rrsig, has_dnskey, has_ds,
        )

        # DNSSEC is considered enabled if ANY reliable signal is positive.
        enabled = ad_flag or has_rrsig or (has_dnskey and has_ds)

        # Status logic and reason.
        reason = ""
        if ad_flag or (has_dnskey and has_ds and has_rrsig):
            check_status = DomainCheckStatus.PASS
        elif enabled:
            # Partial evidence (e.g. RRSIG without DS, or DNSKEY alone).
            check_status = DomainCheckStatus.PASS
        elif has_dnskey or has_ds:
            check_status = DomainCheckStatus.WARNING
            missing = []
            if not has_dnskey:
                missing.append("DNSKEY")
            if not has_ds:
                missing.append("DS")
            reason = (
                f"DNSSEC partially configured — "
                f"missing: {', '.join(missing)}"
            )
        else:
            check_status = DomainCheckStatus.FAIL
            reason = "DNSSEC is not enabled on this domain"

        logger.info(
            "DNSSEC for %s: enabled=%s ad=%s rrsig=%s dnskey=%s ds=%s "
            "method=%s algo=%s",
            domain, enabled, ad_flag, has_rrsig, has_dnskey, has_ds,
            validation_method, algorithm,
        )

        return DnssecInfo(
            status=check_status,
            enabled=enabled,
            ad_flag=ad_flag,
            has_rrsig=has_rrsig,
            rrsig_signer=rrsig_signer,
            ds_records_found=has_ds,
            has_dnskey=has_dnskey,
            algorithm=algorithm,
            validation_method=validation_method,
            reason=reason,
        )

    # -- DNSSEC helpers ------------------------------------------------

    @staticmethod
    def _query_validating_resolver(
        domain: str,
        resolver_ip: str,
    ) -> tuple[bool, bool, str, str]:
        """Query a DNSSEC-validating resolver with the DO flag.

        Returns:
            (ad_flag, has_rrsig, rrsig_signer, algorithm)

        """
        request = dns.message.make_query(
            domain, "A", want_dnssec=True,
        )
        # Set the RD (Recursion Desired) flag — we want the resolver to
        # validate the chain and set the AD flag for us.
        request.flags |= dns.flags.RD

        response = dns.query.udp(request, resolver_ip, timeout=5)

        # 1) Check AD flag.
        ad_flag = bool(response.flags & dns.flags.AD)

        # 2) Scan for RRSIG records in the answer section.
        has_rrsig = False
        rrsig_signer = ""
        algorithm = ""
        rrsig_rdtype = dns.rdatatype.from_text("RRSIG")

        for rrset in response.answer:
            if rrset.rdtype == rrsig_rdtype:
                has_rrsig = True
                for rdata in rrset:
                    # RRSIG rdata has .signer and .algorithm attributes.
                    signer = getattr(rdata, "signer", None)
                    if signer is not None:
                        rrsig_signer = str(signer).rstrip(".")
                    algo_num = getattr(rdata, "algorithm", None)
                    if algo_num is not None:
                        algorithm = DomainSecurityService._dnssec_algorithm_name(
                            algo_num,
                        )
                    break
                break

        return ad_flag, has_rrsig, rrsig_signer, algorithm

    @staticmethod
    def _find_authoritative_ns_ips(
        resolver: dns.resolver.Resolver,
        domain: str,
    ) -> list[str]:
        """Resolve authoritative NS hostnames to IP addresses."""
        ns_ips: list[str] = []
        try:
            ns_answer = resolver.resolve(domain, "NS")
            for rdata in ns_answer:
                ns_host = str(rdata).rstrip(".")
                try:
                    a_answer = resolver.resolve(ns_host, "A")
                    for a_rdata in a_answer:
                        ns_ips.append(str(a_rdata))
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.Timeout,
                ):
                    pass
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
        ):
            pass
        return ns_ips

    @staticmethod
    def _query_with_dnssec(
        domain: str,
        rdtype: str,
        nameserver: str,
    ) -> dns.resolver.Answer | None:
        """Send a DNS query with the DO flag to a specific nameserver."""
        request = dns.message.make_query(
            domain, rdtype, want_dnssec=True,
        )
        response = dns.query.udp(request, nameserver, timeout=5)

        # Look for the requested RRset in the answer section.
        qname = dns.name.from_text(domain)
        target_rdtype = dns.rdatatype.from_text(rdtype)
        for rrset in response.answer:
            if rrset.name == qname and rrset.rdtype == target_rdtype:
                return rrset
        return None

    @staticmethod
    def _pick_validation_method(
        ad_flag: bool,
        has_rrsig: bool,
        has_dnskey: bool,
        has_ds: bool,
    ) -> str:
        """Return a label describing how DNSSEC was confirmed."""
        if ad_flag:
            return "ad_flag"
        if has_rrsig:
            return "rrsig"
        if has_dnskey:
            return "dnskey"
        if has_ds:
            return "ds"
        return ""

    @staticmethod
    def _dnssec_algorithm_name(algo_num: int) -> str:
        """Map DNSSEC algorithm number to a human-readable name."""
        algorithms = {
            1: "RSA/MD5",
            3: "DSA/SHA1",
            5: "RSA/SHA-1",
            6: "DSA-NSEC3-SHA1",
            7: "RSASHA1-NSEC3-SHA1",
            8: "RSA/SHA-256",
            10: "RSA/SHA-512",
            13: "ECDSA/P-256/SHA-256",
            14: "ECDSA/P-384/SHA-384",
            15: "Ed25519",
            16: "Ed448",
        }
        return algorithms.get(algo_num, f"Algorithm-{algo_num}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_summary(
        *checks: WhoisInfo | DnsInfo | SslInfo | HstsInfo | DnssecInfo,
    ) -> ChecksSummary:
        """Aggregate status counts from all check results."""
        counters = {s: 0 for s in DomainCheckStatus}
        for check in checks:
            status = check.status
            if status in counters:
                counters[status] += 1

        total = sum(
            counters[s]
            for s in (
                DomainCheckStatus.PASS,
                DomainCheckStatus.WARNING,
                DomainCheckStatus.FAIL,
                DomainCheckStatus.ERROR,
            )
        )

        return ChecksSummary(
            total=total,
            passed=counters[DomainCheckStatus.PASS],
            warnings=counters[DomainCheckStatus.WARNING],
            failed=counters[DomainCheckStatus.FAIL],
            errors=counters[DomainCheckStatus.ERROR],
        )
