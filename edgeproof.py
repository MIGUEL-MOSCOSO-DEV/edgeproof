import argparse
import http.client
import json
import re
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit


def verify(host, days):
    tls = http.client.HTTPSConnection(host, timeout=8, context=ssl.create_default_context())
    try:
        tls.connect()
        version = tls.sock.version()
        expiration = ssl.cert_time_to_seconds(tls.sock.getpeercert()["notAfter"])
        remaining = int((expiration - time.time()) // 86400)
    finally:
        tls.close()

    plain = http.client.HTTPConnection(host, timeout=8)
    try:
        plain.request("HEAD", "/")
        response = plain.getresponse()
        location = urlsplit(response.getheader("Location") or "")
        redirect = (
            response.status in {301, 302, 303, 307, 308}
            and location.scheme == "https"
            and location.hostname == host
            and location.port in {None, 443}
            and location.username is None
        )
    finally:
        plain.close()
    return {"host": host, "tls": version, "days_remaining": remaining,
            "same_host_https_redirect": redirect,
            "pass": redirect and remaining >= days and version in {"TLSv1.2", "TLSv1.3"}}


def main():
    parser = argparse.ArgumentParser(description="Verifica una política HTTPS de tu dominio.")
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("policy", type=Path)
    parser.add_argument("--authorized", action="store_true")
    args = parser.parse_args()
    if not args.authorized:
        parser.error("Confirma autorización para los dominios de la política.")
    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        hosts, days = policy["hosts"], policy.get("min_certificate_days", 14)
        if type(days) is not int or not 0 <= days <= 365 or not isinstance(hosts, list) or not 1 <= len(hosts) <= 20:
            raise ValueError("Política inválida.")
        pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}"
        if any(not isinstance(host, str) or not re.fullmatch(pattern, host) for host in hosts):
            raise ValueError("Usa nombres DNS en minúsculas, sin URL ni puerto.")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        parser.exit(2, f"{error}\n")
    results = []
    for host in dict.fromkeys(hosts):
        try:
            results.append(verify(host, days))
        except (OSError, ValueError, http.client.HTTPException) as error:
            results.append({"host": host, "error": str(error), "pass": False})
    print(json.dumps(results, indent=2))
    return 2 if any("error" in row for row in results) else int(not all(row["pass"] for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
