from __future__ import annotations

from pydantic import BaseModel, Field

from app.constants import DomainCheckStatus


class WhoisInfo(BaseModel):
    """WHOIS lookup results for a domain.

    Attributes:
        status: Check status (pass / warning / fail / error).
        registrar: Domain registrar name.
        creation_date: Domain creation date.
        expiration_date: Domain expiration date.
        days_until_expiry: Number of days until expiry (negative = expired).
        transfer_locked: Whether clientTransferProhibited is set.
        privacy_enabled: Whether registrant data is anonymized.
        whois_status_codes: Raw WHOIS status codes.
        registrant_name: Registrant name (may be redacted).
        registrant_org: Registrant organization (may be redacted).
        name_servers: List of authoritative name servers.
        error: Error message if the check failed.

    """

    status: str = DomainCheckStatus.SKIPPED
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    days_until_expiry: int | None = None
    transfer_locked: bool = False
    privacy_enabled: bool = False
    whois_status_codes: list[str] = Field(default_factory=list)
    registrant_name: str = ""
    registrant_org: str = ""
    name_servers: list[str] = Field(default_factory=list)
    reason: str = ""
    error: str = ""


class DnsRecord(BaseModel):
    """A single DNS record.

    Attributes:
        record_type: DNS record type (A, AAAA, CNAME, MX, NS, TXT).
        name: Record name.
        value: Record value.
        ttl: Time to live in seconds.

    """

    record_type: str
    name: str = ""
    value: str = ""
    ttl: int = 0


class DnsInfo(BaseModel):
    """DNS record verification results.

    Attributes:
        status: Overall DNS check status.
        records: All discovered DNS records.
        has_a_record: Whether an A record exists.
        has_aaaa_record: Whether an AAAA record exists.
        has_mx_record: Whether MX records exist.
        has_ns_record: Whether NS records exist.
        has_spf: Whether an SPF TXT record exists.
        has_dmarc: Whether a DMARC record exists.
        www_resolves: Whether www subdomain resolves.
        www_redirects_correctly: Whether www redirects to or matches the apex.
        www_target: Target of the www record.
        cloudflare_detected: Whether Cloudflare nameservers are in use.
        cloudflare_proxied: Whether A/AAAA records point to Cloudflare proxy.
        error: Error message if the check failed.

    """

    status: str = DomainCheckStatus.SKIPPED
    records: list[DnsRecord] = Field(default_factory=list)
    has_a_record: bool = False
    has_aaaa_record: bool = False
    has_mx_record: bool = False
    has_ns_record: bool = False
    has_spf: bool = False
    has_dmarc: bool = False
    www_resolves: bool = False
    www_redirects_correctly: bool = False
    www_target: str = ""
    cloudflare_detected: bool = False
    cloudflare_proxied: bool = False
    reason: str = ""
    error: str = ""


class SslInfo(BaseModel):
    """SSL/TLS certificate verification results.

    Attributes:
        status: Check status.
        issuer: Certificate issuer (organization).
        subject: Certificate subject (common name).
        san: Subject Alternative Names.
        valid_from: Certificate validity start date.
        valid_to: Certificate validity end date.
        days_until_expiry: Days until the certificate expires.
        protocol_version: TLS protocol version negotiated.
        is_valid: Whether the certificate chain is trusted.
        error: Error message if the check failed.

    """

    status: str = DomainCheckStatus.SKIPPED
    issuer: str = ""
    subject: str = ""
    san: list[str] = Field(default_factory=list)
    valid_from: str = ""
    valid_to: str = ""
    days_until_expiry: int | None = None
    protocol_version: str = ""
    is_valid: bool = False
    reason: str = ""
    error: str = ""


class HstsInfo(BaseModel):
    """HTTP Strict Transport Security header check results.

    Attributes:
        status: Check status.
        enabled: Whether HSTS header is present.
        max_age: max-age directive value in seconds.
        include_subdomains: Whether includeSubDomains is set.
        preload: Whether preload directive is set.
        raw_header: Raw HSTS header value.
        error: Error message if the check failed.

    """

    status: str = DomainCheckStatus.SKIPPED
    enabled: bool = False
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    raw_header: str = ""
    reason: str = ""
    error: str = ""


class DnssecInfo(BaseModel):
    """DNSSEC validation results.

    Attributes:
        status: Check status.
        enabled: Whether DNSSEC is enabled (validated via AD flag, RRSIG, or DNSKEY).
        ad_flag: Whether the validating resolver set the AD (Authentic Data) flag.
        has_rrsig: Whether RRSIG records were found in the response.
        rrsig_signer: Signer domain extracted from the RRSIG record.
        ds_records_found: Whether DS records are published at the parent.
        has_dnskey: Whether DNSKEY records were found (authoritative or recursive).
        algorithm: DNSSEC signing algorithm.
        validation_method: How DNSSEC was detected (ad_flag, rrsig, dnskey, ds).
        error: Error message if the check failed.

    """

    status: str = DomainCheckStatus.SKIPPED
    enabled: bool = False
    ad_flag: bool = False
    has_rrsig: bool = False
    rrsig_signer: str = ""
    ds_records_found: bool = False
    has_dnskey: bool = False
    algorithm: str = ""
    validation_method: str = ""
    reason: str = ""
    error: str = ""


class ChecksSummary(BaseModel):
    """Aggregate pass/warn/fail counts for all domain checks.

    Attributes:
        total: Total number of checks executed.
        passed: Number of checks that passed.
        warnings: Number of checks with warnings.
        failed: Number of checks that failed.
        errors: Number of checks that errored.

    """

    total: int = 0
    passed: int = 0
    warnings: int = 0
    failed: int = 0
    errors: int = 0


class DomainSecurityReport(BaseModel):
    """Complete domain security audit report.

    Attributes:
        domain: Audited domain name.
        scan_time: ISO-8601 timestamp of the audit.
        whois: WHOIS check results.
        dns: DNS check results.
        ssl: SSL/TLS certificate check results.
        hsts: HSTS header check results.
        dnssec: DNSSEC validation results.
        checks_summary: Aggregate pass/warn/fail counts.

    """

    domain: str = ""
    scan_time: str = ""
    whois: WhoisInfo = Field(default_factory=WhoisInfo)
    dns: DnsInfo = Field(default_factory=DnsInfo)
    ssl: SslInfo = Field(default_factory=SslInfo)
    hsts: HstsInfo = Field(default_factory=HstsInfo)
    dnssec: DnssecInfo = Field(default_factory=DnssecInfo)
    checks_summary: ChecksSummary = Field(default_factory=ChecksSummary)
