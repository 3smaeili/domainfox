import nmap


class WAFDetection:
    """
    WAFDetection performs WAF detection on a target host using Nmap's scripting engine.

    attrs:
        host (str): The target host (IP or domain) to scan.
        ports (str, optional): Comma-separated list of ports to scan. Defaults to top 100 ports if not provided.
    """

    def __init__(self, host: str, ports: str = None) -> None:
        self.host = host
        self.ports = ports

    def scan(self) -> dict | None:
        scanner = nmap.PortScanner()
        if self.ports:
            res: dict = scanner.scan(
                hosts=self.host,
                ports=self.ports,
                arguments="--script http-waf-detect",
            )
        else:
            res: dict = scanner.scan(
                hosts=self.host,
                arguments="--top-ports 100 --script http-waf-detect",
            )
        return WAFDetection.__parse(res)

    @staticmethod
    def __parse(res: dict) -> dict | None:
        if scan := res.get("scan"):
            for scan_val in scan.values():
                if tcp := scan_val.get("tcp"):
                    for tcp_val in tcp.values():
                        if script := tcp_val.get("script"):
                            return script
