import subprocess
import platform
import json
import re


class TraceRoute:
    """
    TraceRoute runs a traceroute to a specified host and parses the results.

    attrs:
        host (str): The destination host to trace the route to.
    """

    def __init__(self, host: str) -> None:
        self.host = host

    def traceroute(self) -> list | str:
        is_win = platform.system() == "Windows"
        cmd = ["tracert", self.host] if is_win else ["traceroute", self.host]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode == 0:
                if is_win:
                    return TraceRoute.__parse_windows(result.stdout)
                else:
                    TraceRoute.__parse_linux(result.stdout)
            else:
                return json.dumps({"error": result.stderr})
        except Exception as e:
            return json.dumps({"error": e.__str__()})

    @staticmethod
    def __parse_windows(output: str) -> list:
        hops = []
        for line in output.splitlines():
            match = re.match(
                r"\s*(\d+)\s+<*([\d\.]+ ms|Request timed out.)\s+<*([\d\.]+ ms|Request timed out.)\s+<*([\d\.]+ ms|Request timed out.)\s+(.*)",
                line,
            )
            if match:
                hops.append(
                    {
                        "hop": int(match.group(1)),
                        "times": [
                            match.group(2),
                            match.group(3),
                            match.group(4),
                        ],
                        "host": match.group(5),
                    }
                )
        return hops

    @staticmethod
    def __parse_linux(output: str) -> list:
        hops = []
        for line in output.splitlines():
            match = re.match(
                r"\s*(\d+)\s+([^\s]+)\s+\(([\d\.]+)\)\s+([\d\.]+\s+ms)\s+([\d\.]+\s+ms)\s+([\d\.]+\s+ms)",
                line,
            )
            if match:
                hops.append(
                    {
                        "hop": int(match.group(1)),
                        "host": match.group(2),
                        "ip": match.group(3),
                        "times": [
                            match.group(4),
                            match.group(5),
                            match.group(6),
                        ],
                    }
                )
        return hops
