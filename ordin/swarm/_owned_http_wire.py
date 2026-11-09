import hashlib
import hmac
from urllib.parse import urlsplit


def request_bytes(url, headers, credential=None):
    """Only GET, no query/body/redirect/proxy, with fixed transport framing."""
    if (
        type(url) is not str
        or len(url) > 4096
        or not url.isascii()
        or "?" in url
        or "#" in url
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
    ):
        raise ValueError("literal bounded exact HTTP URL required")
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.netloc.isascii()
        or not path.isascii()
        or any(ord(char) <= 32 or ord(char) == 127 for char in parsed.netloc + path)
    ):
        raise ValueError("literal HTTP request line required")
    parts = [
        f"GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
    ]
    if len(headers) > 16:
        raise ValueError("bounded exact HTTP headers required")
    seen = set()
    forbidden = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "te",
        "trailer",
        "authorization",
        "proxy-authorization",
        "cookie",
        "accept-encoding",
        "x-api-key",
    }
    for name, value in headers:
        # Worker independently rejects framing/duplicate/injection ambiguity.
        if (
            type(name) is not str
            or not name.isascii()
            or not 1 <= len(name) <= 128
            or any(
                char
                not in "!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
                for char in name
            )
            or name.lower() in seen
            or name.lower() in forbidden
            or name.lower().startswith("proxy-")
            or type(value) is not str
            or not value.isascii()
            or len(value) > 2048
            or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("ambiguous exact HTTP header")
        seen.add(name.lower())
        parts.append(f"{name}: {value}\r\n")
    if credential is not None:
        if (
            type(credential) is not bytes
            or not 1 <= len(credential) <= 16384
            or any(value < 33 or value > 126 for value in credential)
        ):
            raise ValueError("private bounded bearer credential required")
        parts.append("Authorization: Bearer " + credential.decode("ascii") + "\r\n")
    raw = ("".join(parts) + "\r\n").encode("ascii")
    if len(raw) > 65536:
        raise ValueError("owned HTTP request exceeds wire bound")
    return raw


def request_tag(key, raw):
    # A keyed tag binds private Authorization bytes without publishing an
    # offline dictionary-checkable digest of those bytes.
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def read_response(connection, maximum, *, require_length=False):
    """Strict bounded HTTP/1 framing; endpoint bytes remain untrusted data."""
    if type(maximum) is not int or not 1 <= maximum <= 65536:
        raise ValueError("bounded HTTP response required")
    incoming = bytearray()
    while b"\r\n\r\n" not in incoming:
        # No body read-ahead can consume the route's independent byte budget.
        # Header text is capped separately; SSL recv flags cannot safely use
        # MSG_PEEK, so read exactly through the one bounded delimiter.
        chunk = connection.recv(1)
        if not chunk:
            raise ValueError("incomplete HTTP headers")
        incoming.extend(chunk)
        if len(incoming) > 8192:
            raise ValueError("HTTP header bound exceeded")
    raw_headers, body = bytes(incoming).split(b"\r\n\r\n", 1)
    lines = raw_headers.decode("ascii").split("\r\n")
    status = lines[0].split(" ", 2)
    if (
        len(status) < 2
        or status[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(status[1]) != 3
        or not status[1].isdigit()
    ):
        raise ValueError("unsupported HTTP status line")
    number = int(status[1])
    if any(ord(char) < 32 or ord(char) == 127 for char in lines[0]):
        raise ValueError("malformed HTTP status line")
    if not (200 <= number <= 299 or 400 <= number <= 599):
        raise ValueError("HTTP interim responses and redirects unsupported")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line or line[0].isspace() or len(fields) >= 64:
            raise ValueError("ambiguous HTTP response headers")
        name, value = line.split(":", 1)
        lowered = name.lower()
        if (
            not name
            or any(
                char
                not in "!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
                for char in name
            )
            or lowered in fields
            or any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value)
        ):
            raise ValueError("duplicate or malformed HTTP response header")
        fields[lowered] = value.strip(" \t")
    if (
        "transfer-encoding" in fields
        or fields.get("content-encoding", "identity").lower() != "identity"
    ):
        raise ValueError("chunked or encoded HTTP response unsupported")
    length = fields.get("content-length")
    if length is not None:
        if not length.isascii() or not length.isdigit() or len(length) > 6 or int(length) > maximum:
            raise ValueError("HTTP response length exceeds bound")
        expected = int(length)
        if number == 204 and expected != 0:
            raise ValueError("204 response cannot carry a body")
    elif number == 204:
        expected = 0
    elif require_length:
        raise ValueError("TLS response requires an explicit bounded content length")
    else:
        expected = None
    result = bytearray(body)
    while True:
        if len(result) > maximum or expected is not None and len(result) > expected:
            raise ValueError("HTTP body exceeds exact framing bound")
        limit = maximum if expected is None else expected
        chunk = connection.recv(min(4096, limit + 1 - len(result)))
        if not chunk:
            break
        result.extend(chunk)
    if expected is not None and len(result) != expected:
        raise ValueError("HTTP response body incomplete")
    return bytes(result)
