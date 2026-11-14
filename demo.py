from unittest.mock import patch
import edgeproof

with patch("edgeproof.http.client.HTTPSConnection") as https, patch("edgeproof.http.client.HTTPConnection") as http:
    https.return_value.sock.version.return_value = "TLSv1.3"
    https.return_value.sock.getpeercert.return_value = {"notAfter": "Jan 01 00:00:00 2030 GMT"}
    response = http.return_value.getresponse.return_value
    response.status = 301
    response.getheader.return_value = "https://web.example.com/"
    result = edgeproof.verify("web.example.com", 14)
    assert result["pass"]
    response.getheader.return_value = "https://other.example.com/"
    assert not edgeproof.verify("web.example.com", 14)["pass"]
    print("DEMO | HTTPS policy with simulated responses")
    print("PASS  TLS 1.3 and valid certificate lifetime")
    print("PASS  HTTP redirects to HTTPS on the same host")
    print("FAIL  Redirect to a different host (expected)")
