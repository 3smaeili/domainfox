import requests


class SubDomain:
    """
    SubDomain queries https://crt.sh for subdomains associated with a domain.

    attrs:
        domain (str): The main domain to search subdomains for.
        headers (dict): Optional HTTP headers for requests.
        timeout (int): Request timeout in seconds (default: 20).
    """

    def __init__(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        self.domain = domain
        self.headers = headers
        self.timeout = timeout

    def fetch(self) -> list:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    if name_value := entry.get("name_value"):
                        for subdomain in name_value.split("\n"):
                            if subdomain.endswith(self.domain):
                                subdomains.add(subdomain.lower())
                return sorted(subdomains)
            return [response.status_code]
        except Exception as e:
            return [e.__str__()]
