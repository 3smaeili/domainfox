import ssl
import socket
import contextlib
import warnings
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class SSLCertificate:
    """
    SSLCertificate fetches and parses SSL certificate information from a given host and port.

    attrs:
        host (str): The target hostname.
        port (int): The port number (usually 443 for HTTPS).
    """

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def certificate(self) -> dict:
        certificate = "n/a"
        pem_data = None
        with contextlib.suppress(Exception):
            pem_data = bytes(ssl.get_server_certificate((self.host, self.port)), "utf-8")

        if pem_data:
            certificate = {}
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())

            certificate["version"] = cert.version.name
            certificate["serial"] = cert.serial_number
            certificate["issuer"] = {attr.oid._name: str(attr.value) for attr in cert.issuer}
            certificate["validity"] = {
                "not_valid_before": cert.not_valid_before.__str__(),
                "not_valid_after": cert.not_valid_after.__str__(),
            }
            certificate["fingerprints"] = {
                "SHA256": str(cert.fingerprint(hashes.SHA256())),
                "SHA1": str(cert.fingerprint(hashes.SHA1())),
            }
            certificate["extensions"] = SSLCertificate.__extensions(cert)
            certificate["ciphers"] = self.supported_ciphers()

        return certificate

    @staticmethod
    def __extensions(cert: x509.Certificate) -> dict:
        ext_dict = {}
        for ext in cert.extensions:
            ext_name = ext.oid._name if ext.oid._name else str(ext.oid)
            ext_dict[ext_name] = {"critical": str(ext.critical), "value": str(ext.value)}
        return ext_dict

    def supported_ciphers(self) -> list:
        available_ciphers = ssl.create_default_context().get_ciphers()
        supported_ciphers = []

        for cipher in available_ciphers:
            cipher_name = cipher["name"]
            with contextlib.suppress(Exception):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(cipher_name)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((self.host, self.port), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host):
                        supported_ciphers.append(cipher_name)

        return supported_ciphers
