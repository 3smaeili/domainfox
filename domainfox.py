import sys
import subprocess
import contextlib
import re
import json
import validators
from argparse import ArgumentParser, Namespace
from threading import Thread
from colorama import Fore
from recon import DomainfoxRecon


class Domainfox(DomainfoxRecon):
    """
    Domainfox class executes multiple reconnaissance tasks on a given domain.
    extends DomainfoxRecon which contains individual recon methods.

    args:
        args (Namespace): Parsed command-line arguments.

    attrs:
        domain (str): Target domain.
        output (str|None): Output file path, if provided.
        dns_records (bool): Whether to perform DNS record checks.
        ip_info (bool): Whether to fetch IP info and headers.
        seo_info (bool): Whether to fetch SEO-related information.
        snapshots (bool): Whether to fetch webpage snapshots.
        ssl_cert (bool): Whether to fetch SSL certificate info.
        sub_domain (bool): Whether to enumerate subdomains.
        traceroute (bool): Whether to run traceroute.
        waf_check (bool): Whether to detect Web Application Firewalls.
        whois_lookup (bool): Whether to perform WHOIS lookup.
        ip_addr (str|None): The resolved IP address of the domain.
    """

    def __init__(self, args: Namespace):
        super().__init__()

        self.domain = args.domain
        self.output = args.output
        self.dns_records = not args.no_dnsrec
        self.ip_info = not args.no_ipinfo
        self.seo_info = not args.no_seoinfo
        self.snapshots = not args.no_snapshot
        self.ssl_cert = not args.no_sslcert
        self.sub_domain = not args.no_subdomain
        self.traceroute = not args.no_tracert
        self.waf_check = not args.no_wafcheck
        self.whois_lookup = not args.no_whois
        self.ip_addr = self.ipaddr()

    def recon(self):
        if not validators.domain(self.domain):
            Domainfox.error("Invalid domain")

        conf = Domainfox.config()
        threads = []

        if self.dns_records:
            threads.append(
                Thread(
                    target=self.dnsrec,
                    args=(self.domain, conf.get("dns_rtypes")),
                )
            )
        if self.ip_info:
            threads.append(
                Thread(
                    target=self.ipinfo,
                    args=(self.domain, conf.get("http_headers"), conf.get("http_timeout")),
                )
            )
        if self.seo_info:
            url = f"https://www.{self.domain}" if conf.get("https") else f"http://www.{self.domain}"
            threads.append(
                Thread(
                    target=self.seoinfo,
                    args=(
                        url,
                        conf.get("http_headers"),
                        conf.get("http_timeout"),
                        conf.get("social_media"),
                    ),
                )
            )
        if self.snapshots:
            threads.append(
                Thread(
                    target=self.snapshot,
                    args=(self.domain, conf.get("http_headers"), conf.get("http_timeout")),
                )
            )
        if self.ssl_cert:
            threads.append(
                Thread(
                    target=self.sslcert,
                    args=(self.ip_addr, conf.get("ssl_port")),
                )
            )
        if self.sub_domain:
            threads.append(
                Thread(
                    target=self.subdomain,
                    args=(self.domain, conf.get("http_headers"), conf.get("http_timeout")),
                )
            )
        if self.traceroute:
            threads.append(
                Thread(
                    target=self.tracert,
                    args=(self.ip_addr,),
                )
            )
        if self.waf_check:
            threads.append(
                Thread(
                    target=self.wafcheck,
                    args=(self.domain, conf.get("waf_port")),
                )
            )
        if self.whois_lookup:
            threads.append(
                Thread(
                    target=self.whois,
                    args=(self.domain, conf.get("http_headers"), conf.get("http_timeout")),
                )
            )

        _ = [t.start() for t in threads]
        _ = [t.join() for t in threads]

        if self.output:
            Domainfox.output_file(self.output, self.results)
            print("\n[ * ] Done!\n")
            sys.exit(0)

        Domainfox.print_results(self.results)
        print("\n[ * ] Done!\n")
        sys.exit(0)

    def ipaddr(self) -> str | None:
        with contextlib.suppress(Exception):
            cmd = f"ping {self.domain} -c 1"
            pong = subprocess.check_output(cmd, shell=True, text=True).splitlines()[0]
            return re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", pong)[0]

    @staticmethod
    def config() -> dict:
        with open("./conf.json", "r") as file:
            conf: dict = json.load(file)

        return {
            "http_headers": conf.get("HTTP_REQ_HEADERS"),
            "http_timeout": conf.get("HTTP_REQ_TIMEOUT"),
            "https": conf.get("HTTPS"),
            "tcp_timeout": conf.get("TCP_CONN_TIMEOUT"),
            "ssl_port": conf.get("SSL_PORT"),
            "waf_port": conf.get("WAF_PORT"),
            "dns_rtypes": conf.get("DNS_RTYPES"),
            "social_media": conf.get("SOCIAL_MEDIA"),
        }

    @staticmethod
    def output_file(path: str, results: dict) -> None:
        with open(path, "w") as file:
            json.dump(results, file, indent=4)

    @staticmethod
    def print_results(results: dict) -> None:
        print("\n[ * ] Result:")
        print(json.dumps(results, indent=4))

    @staticmethod
    def error(msg: str) -> None:
        print(Fore.RED + f"\n[ ! ] {msg}\n")
        sys.exit(1)


if __name__ == "__main__":
    BANNER = r"""
       __                      _       ____                
  ____/ /___  ____ ___  ____ _(_)___  / __/___  _  __      
 / __  / __ \/ __ `__ \/ __ `/ / __ \/ /_/ __ \| |/_/    
/ /_/ / /_/ / / / / / / /_/ / / / / / __/ /_/ />  <      
\__,_/\____/_/ /_/ /_/\__,_/_/_/ /_/_/  \____/_/|_|      

- Domain Information Extractor - v1.0.0                   
- https://www.github.com/3smaeili/domainfox

"""
    print(Fore.GREEN + BANNER + Fore.WHITE)
    parser = ArgumentParser(prog="domainfox", usage="python domainfox.py <DOMAIN> [OPTION]")
    parser.add_argument("domain", type=str, help="Specific domain. Ex: example.com")
    parser.add_argument("--output", help="Path to the result file (JSON file - Ex: result.json).")
    parser.add_argument("--no-dnsrec", action="store_true", help="Disable DNS record fetching.")
    parser.add_argument("--no-ipinfo", action="store_true", help="Disable Host information fetching.")
    parser.add_argument("--no-seoinfo", action="store_true", help="Disable SEO information fetching.")
    parser.add_argument("--no-snapshot", action="store_true", help="Disable Snapshot fetching.")
    parser.add_argument("--no-sslcert", action="store_true", help="Disable SSL certificate fetching.")
    parser.add_argument("--no-subdomain", action="store_true", help="Disable subdomains fetching.")
    parser.add_argument("--no-tracert", action="store_true", help="Disable traceroute.")
    parser.add_argument("--no-wafcheck", action="store_true", help="Disable WAF checking.")
    parser.add_argument("--no-whois", action="store_true", help="Disable Whois lookup.")
    args = parser.parse_args()

    domainfox = Domainfox(args)
    domainfox.recon()
