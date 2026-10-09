"""ArtifactStore: where files survive after the sandbox that made them is destroyed.

S3 API through boto3, so the same code talks to a local RustFS/Garage/SeaweedFS container in
development and to Vultr Object Storage (or any S3 endpoint) on the VM: only env vars change.

Trust model: object *names and bytes* originate inside a sandbox, i.e. from an attacker. So
- names are validated here (and again by the exporter) and are never joined onto a host path;
  they only ever become part of an S3 key under tasks/<task_id>/;
- the store never decides what a file *is*: the API picks a safe Content-Type on the way out
  (see serve.py), and the ledger records each object's SHA-256 so tampering is detectable.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Protocol

TASK_ID_RE = re.compile(r"^[0-9a-f]{8}$")
# Segments: unicode word chars plus a few harmless punctuation marks. No "..", no leading "/".
_SEG_OK = re.compile(r"^[\w][\w.+@,=()\[\] -]{0,119}$")
MAX_NAME_LEN = 300
MAX_DEPTH = 8
KINDS = ("file", "screenshot")


class ArtifactError(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def valid_name(name: str) -> bool:
    """A relative, normalised, shallow path made of plain segments."""
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_LEN or name.startswith("/"):
        return False
    parts = name.split("/")
    return len(parts) <= MAX_DEPTH and all(p not in (".", "..") and _SEG_OK.match(p) for p in parts)


def object_key(task_id: str, name: str) -> str:
    if not TASK_ID_RE.match(task_id or ""):
        raise ArtifactError("bad task id")
    if not valid_name(name):
        raise ArtifactError("bad artifact name")
    return f"tasks/{task_id}/{name}"


class ArtifactStore(Protocol):
    def ping(self) -> None: ...                       # raises if the backend is unreachable
    def put(self, task_id: str, name: str, data: bytes) -> dict: ...   # {"bytes", "sha256"}
    def get(self, task_id: str, name: str) -> bytes | None: ...


class MemoryArtifactStore:
    """Tests and Docker-free development. Same contract as the S3 store."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def ping(self) -> None:
        return None

    def put(self, task_id, name, data):
        self.objects[object_key(task_id, name)] = bytes(data)
        return {"bytes": len(data), "sha256": sha256_hex(data)}

    def get(self, task_id, name):
        return self.objects.get(object_key(task_id, name))


class S3ArtifactStore:
    def __init__(self, client, bucket: str):
        self.client, self.bucket = client, bucket

    # ---- construction ------------------------------------------------------------
    @classmethod
    def from_env(cls, env=None):
        """None if unconfigured (artifacts are then simply not attached, like the egress proxy)."""
        e = os.environ if env is None else env
        endpoint, access, secret = (e.get(k, "") for k in (
            "MINILOCKER_S3_ENDPOINT", "MINILOCKER_S3_ACCESS_KEY", "MINILOCKER_S3_SECRET_KEY"))
        if not (endpoint and access and secret):
            return None
        import boto3
        from botocore.config import Config
        client = boto3.client(
            "s3", endpoint_url=endpoint, aws_access_key_id=access, aws_secret_access_key=secret,
            region_name=e.get("MINILOCKER_S3_REGION", "us-east-1"),
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                          connect_timeout=3, read_timeout=15, retries={"max_attempts": 2}))
        store = cls(client, e.get("MINILOCKER_S3_BUCKET", "minilocker-artifacts"))
        store.ensure_bucket()
        return store

    def ensure_bucket(self) -> None:
        from botocore.exceptions import ClientError
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError as e:
            code = str(e.response.get("Error", {}).get("Code", ""))
            if code not in ("404", "NoSuchBucket", "NotFound"):
                raise
            self.client.create_bucket(Bucket=self.bucket)

    # ---- contract ----------------------------------------------------------------
    def ping(self) -> None:
        self.client.head_bucket(Bucket=self.bucket)

    def put(self, task_id, name, data):
        # Always stored as opaque bytes: a sandbox cannot choose how its file is later served.
        self.client.put_object(Bucket=self.bucket, Key=object_key(task_id, name), Body=bytes(data),
                               ContentType="application/octet-stream")
        return {"bytes": len(data), "sha256": sha256_hex(data)}

    def get(self, task_id, name):
        from botocore.exceptions import ClientError
        try:
            return self.client.get_object(Bucket=self.bucket, Key=object_key(task_id, name))["Body"].read()
        except ClientError as e:
            if str(e.response.get("Error", {}).get("Code", "")) in ("NoSuchKey", "404", "NotFound"):
                return None
            raise
