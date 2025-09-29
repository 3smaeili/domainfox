import dns.resolver


class DNSRecords:
    """
    DNSRecords queries and returns DNS records of specified types for a given domain.

    attrs:
        domain (str): The domain name to query DNS records for.
        rtypes (list[str]): A list of DNS record types to retrieve (e.g., ['A', 'MX']).
    """

    def __init__(self, domain: str, rtypes: list[str]) -> None:
        self.domain = domain
        self.rtypes = rtypes

    def resolve(self) -> dict:
        result = {}

        for rtype in self.rtypes:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, raise_on_no_answer=False)
                result[rtype] = [rdata.to_text() for rdata in answers]
            except dns.resolver.NoAnswer:
                result[rtype] = "no_answer"
            except dns.resolver.NXDOMAIN:
                result[rtype] = "domain_does_not_exist"
            except dns.resolver.NoNameservers:
                result[rtype] = "no_nameservers_available"
            except Exception as e:
                result[rtype] = e.__str__()

        return result
