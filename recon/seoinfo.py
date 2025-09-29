import requests
from bs4 import BeautifulSoup


class SEOBasicInfo:
    """
    SEOBasicInfo extracts basic SEO metadata from a webpage.

    attrs:
        url (str): The URL to fetch the page from (optional if HTML is provided).
        html_content (str): Pre-fetched HTML content (optional).
        headers (dict): HTTP request headers (optional).
        timeout (int): Timeout in seconds for HTTP requests.
        social (list[str]): List of keywords (e.g., 'facebook', 'linkedin') to identify social media links.
    """

    def __init__(
        self,
        url: str = None,
        html_content: str = None,
        headers: dict = None,
        timeout: int = 20,
        social_media: list[str] = [],
    ) -> None:
        self.html_content = html_content
        self.url = url
        self.timeout = timeout
        self.headers = headers
        self.social = social_media

    def fetch(self) -> dict | str:
        try:
            resp = (
                self.html_content
                if self.html_content
                else requests.get(url=self.url, headers=self.headers, timeout=self.timeout)
            )
            return SEOBasicInfo.__parse(resp, self.social)
        except requests.exceptions.RequestException as e:
            return e.__str__()

    @staticmethod
    def __parse(data: requests.Response, social: list[str]) -> dict:
        soup = BeautifulSoup(data.text, "html.parser")
        title = soup.title.string if soup.title else "n/a"
        description = soup.find("meta", attrs={"name": "description"})
        keywords = soup.find("meta", attrs={"name": "keywords"})
        h1_tags = [h1.get_text(strip=True) for h1 in soup.find_all("h1")]
        social_links = {a["href"] for a in soup.find_all("a", href=True) if any(s in a["href"] for s in social)}

        return {
            "title": title,
            "description": str(description["content"]) if description else "n/a",
            "keywords": str(keywords["content"]).split(" ") if keywords else "n/a",
            "h1_tags": h1_tags,
            "social_links": list(social_links) if social_links else "n/a",
        }
