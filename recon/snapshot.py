import requests


class WaybackSnapshots:
    """
    WaybackSnapshots queries the Internet Archive for the closest archived snapshot of a domain.

    attrs:
        domain (str): The domain to check for archived snapshots.
        headers (dict): Optional HTTP headers for the request.
        timeout (int): Timeout for the HTTP request in seconds (default: 20).
    """

    def __init__(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        self.domain = domain
        self.headers = headers
        self.timeout = timeout

    def snapshot(self) -> dict | str:
        params = {"url": f"http://{self.domain}"}

        try:
            resp = requests.get(
                "https://archive.org/wayback/available",
                params=params,
                headers=self.headers,
                timeout=self.timeout,
            ).json()
        except Exception as e:
            return e.__str__()

        if resp.get("archived_snapshots"):
            closest = resp["archived_snapshots"].get("closest")
            if closest:
                closest_snapshot_url: str = closest.get("url")
                if closest_snapshot_url[:5] == "http:":
                    closest_snapshot_url = closest_snapshot_url.replace("http:", "https:", 1)
                return {
                    "closest_snapshot_url": closest_snapshot_url,
                    "timestamp": closest.get("timestamp"),
                    "status": closest.get("status"),
                }
