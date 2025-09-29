from threading import Lock

from .dnsrec import DNSRecords
from .ipinfo import IPInfo
from .seoinfo import SEOBasicInfo
from .snapshot import WaybackSnapshots
from .sslcert import SSLCertificate
from .subdomain import SubDomain
from .tracert import TraceRoute
from .wafcheck import WAFDetection
from .whois import WhoisDomainLookup


class DomainfoxRecon:

    def __init__(self) -> None:
        self.trd_lock = Lock()
        self.results = {}

    def dnsrec(self, domain: str, rtypes: list[str]) -> None:
        dnsrec = DNSRecords(domain, rtypes)
        info = dnsrec.resolve()
        with self.trd_lock:
            self.results["dns_records"] = info
            print("-> DNS records checked")

    def ipinfo(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        ipinfo = IPInfo(domain, headers, timeout)
        info = ipinfo.info()
        with self.trd_lock:
            self.results["ip_info"] = info
            print("-> IP Info checked")

    def seoinfo(
        self,
        url: str = None,
        headers: dict = None,
        timeout: int = 20,
        social_media: list[str] = [],
    ) -> None:
        seoinfo = SEOBasicInfo(url, None, headers, timeout, social_media)
        info = seoinfo.fetch()
        with self.trd_lock:
            self.results["seo_basic_info"] = info
            print("-> SEO basic information checked")

    def snapshot(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        snapshot = WaybackSnapshots(domain, headers, timeout)
        info = snapshot.snapshot()
        with self.trd_lock:
            self.results["snapshots"] = info
            print("-> Snapshots checked")

    def sslcert(self, host: str, port: int) -> None:
        sslcert = SSLCertificate(host, port)
        info = sslcert.certificate()
        with self.trd_lock:
            self.results["ssl"] = info
            print("-> SSL Certificate checked")

    def subdomain(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        subdomain = SubDomain(domain, headers, timeout)
        info = subdomain.fetch()
        with self.trd_lock:
            self.results["subdomains"] = info
            print("-> Subdomains checked")

    def tracert(self, domain: str) -> None:
        tracert = TraceRoute(domain)
        info = tracert.traceroute()
        with self.trd_lock:
            self.results["traceroute"] = info
            print("-> Traceroute checked")

    def wafcheck(self, host: str, ports: str) -> None:
        wafcheck = WAFDetection(host, ports)
        info = wafcheck.scan()
        with self.trd_lock:
            self.results["waf"] = info
            print("-> WAF checked")

    def whois(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        whois = WhoisDomainLookup(domain, headers, timeout)
        info = whois.whois().result
        with self.trd_lock:
            self.results["whois"] = info
            print("-> Whois lookup checked")
