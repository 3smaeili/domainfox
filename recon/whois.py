import requests


class WhoisDomainLookup:
    """
    Performs WHOIS lookups via IANA and parses the response into structured JSON format.

    attrs:
        domain (str): The domain to perform a WHOIS lookup on.
        headers (dict, optional): Optional headers for the HTTP request.
        timeout (int): Request timeout in seconds.
        result (dict): Structured result containing WHOIS details.
    """

    def __init__(self, domain: str, headers: dict = None, timeout: int = 20) -> None:
        self.headers = headers
        self.timeout = timeout
        self.domain = domain
        self.result = {
            "organization": "n/a",
            "contact": [],
            "nserver": [],
            "source": "IANA",
        }

    def whois(self) -> "WhoisDomainLookup":
        url = f"https://www.iana.org/whois?q={self.domain}"

        try:
            resp = requests.get(url=url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            raise e

        self.json_fmt(resp.text)
        return self

    def json_fmt(self, data: str) -> dict:
        data = data[data.index("<pre>") : data.index("</pre>")].split("\n\n")
        data = [item for item in data if item and "%" not in item]

        for item in data:
            title = item.split(":")[0].strip()

            match title:
                case "organisation":
                    self.result["organization"] = WhoisDomainLookup.__organization(item)
                case "contact":
                    self.result["contact"].append(WhoisDomainLookup.__contact(item))
                case "nserver":
                    self.result["nserver"].extend(WhoisDomainLookup.__nserver(item))

        if not self.result["contact"]:
            self.result["contact"] = "n/a"
        if not self.result["nserver"]:
            self.result["nserver"] = "n/a"

        return self

    @staticmethod
    def __organization(data: str) -> dict:
        org = {"name": "", "address": "", "phone": "", "fax": "", "email": ""}
        data: list = [(k.strip(), v.strip()) for k, v in (item.split(":") for item in data.split("\n"))]

        for key, val in iter(data):
            match key:
                case "organisation":
                    org["name"] = val
                case "phone":
                    org["phone"] = val
                case "fax-no":
                    org["fax"] = val
                case "e-mail":
                    org["email"] = val
                case "address":
                    org["address"] = f"{val}, {org['address']}"

        return org

    @staticmethod
    def __contact(data: str) -> dict:
        contact = {"title": "", "name": "", "organization": {}}

        if "organisation" in data:
            contact["organization"] = WhoisDomainLookup.__organization(data[data.index("organisation") :])

        data: list = [(k.strip(), v.strip()) for k, v in (item.split(":") for item in data.split("\n"))]

        for key, val in iter(data):
            match key:
                case "contact":
                    contact["title"] = val
                case "name":
                    contact["name"] = val

        return contact

    @staticmethod
    def __nserver(data: str) -> list:
        return [item[1].strip() for item in (ns.split(":") for ns in data.split("\n"))]
