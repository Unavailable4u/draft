"""How artifact bytes leave the API.

Artifact content is attacker-controlled (an agent that read a hostile page can write any file).
Serving it from the control plane's origin as text/html or image/svg+xml would be stored XSS
on the origin that holds the API token. So the Content-Type is NEVER taken from the sandbox:
only a few raster image types, confirmed by magic bytes, are shown inline; everything else is
an opaque download. The UI previews text itself, as text, never as markup.
"""
import posixpath
import re
from urllib.parse import quote

_IMAGES = {
    "png": ("image/png", lambda b: b.startswith(b"\x89PNG\r\n\x1a\n")),
    "jpg": ("image/jpeg", lambda b: b.startswith(b"\xff\xd8\xff")),
    "jpeg": ("image/jpeg", lambda b: b.startswith(b"\xff\xd8\xff")),
    "gif": ("image/gif", lambda b: b[:6] in (b"GIF87a", b"GIF89a")),
    "webp": ("image/webp", lambda b: b[:4] == b"RIFF" and b[8:12] == b"WEBP"),
}


def serve_headers(name: str, data: bytes):
    """(media_type, headers) for an artifact response."""
    base = posixpath.basename(name) or "artifact"
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
    media, inline = "application/octet-stream", False
    if ext in _IMAGES and _IMAGES[ext][1](data[:16]):
        media, inline = _IMAGES[ext][0], True
    ascii_name = re.sub(r'[^A-Za-z0-9._-]', "_", base)[:100] or "artifact"
    disp = "inline" if inline else "attachment"
    return media, {
        "Content-Disposition": f"{disp}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(base)}",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "private, max-age=300",
    }
