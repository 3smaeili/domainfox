import re
import subprocess
import contextlib
import socket
import requests


class IPInfo:
    """
    IPInfo retrieves IP address details and geolocation data for a domain.

    attrs:
        domain (str): The domain name to investigate.
        headers (dict, optional): Optional headers to include in the HTTP request to ipinfo.io.
        timeout (int): Request timeout in seconds (default: 20).
    """

    def __init__(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        self.domain = domain
        self.headers = headers
        self.timeout = timeout

    def info(self) -> dict | str:
        if host := self.ipaddr():
            info = {"host": host, "hostname": IPInfo.hostname(host), "geo": "n/a"}
            resp = requests.get(
                url=f"https://ipinfo.io/{host}/json",
                headers=self.headers,
                timeout=self.timeout,
            )
            if resp.status_code in range(100, 400):
                data: dict = resp.json()
                info["geo"] = {
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "loc": data.get("loc"),
                    "source": "https://ipinfo.io",
                }
            else:
                info["geo"] = {
                    "exception": {"status": resp.status_code, "message": resp.text},
                    "source": "https://ipinfo.io",
                }
            return info
        return "n/a"

    def ipaddr(self) -> str | None:
        with contextlib.suppress(Exception):
            cmd = f"ping {self.domain} -c 1"
            pong = subprocess.check_output(cmd, shell=True, text=True).splitlines()[0]
            return re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", pong)[0]

    @staticmethod
    def hostname(ip: str) -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return "n/a"
