"""deploy/bootstrap.sh --env-only: the part of the bootstrap that does not need Docker."""
import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "bootstrap.sh"


def run(env_file: Path):
    return subprocess.run(["bash", str(SCRIPT), "--env-only"], capture_output=True, text=True,
                          env={**os.environ, "MINILOCKER_BOOTSTRAP_ENV_FILE": str(env_file)})


def values(env_file: Path) -> dict:
    out = {}
    for line in env_file.read_text().replace("\r", "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v
    return out


def test_a_fresh_machine_gets_secrets_and_is_told_what_is_missing(tmp_path):
    env = tmp_path / ".env"
    r = run(env)
    assert r.returncode == 2
    # the example pre-fills the provider URL and model, so only the key is genuinely missing
    assert "LLM_API_KEY" in r.stderr and "LLM_MODEL" not in r.stderr and "LLM_BASE_URL" not in r.stderr
    v = values(env)
    assert len(v["MINILOCKER_API_TOKEN"]) == 48 and len(v["MINILOCKER_S3_SECRET_KEY"]) == 48
    assert v["MINILOCKER_S3_ACCESS_KEY"] == "minilocker"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600                  # secrets are not world-readable


def test_a_dev_env_with_windows_line_endings_is_completed_not_clobbered(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes(b"LLM_BASE_URL=https://api.groq.com/openai/v1\r\nLLM_MODEL=openai/gpt-oss-120b\r\n"
                    b"LLM_API_KEY=gsk_secret\r\n")
    r = run(env)
    assert r.returncode == 0, r.stderr
    v = values(env)
    assert v["LLM_API_KEY"] == "gsk_secret" and v["LLM_MODEL"] == "openai/gpt-oss-120b"   # untouched
    assert len(v["MINILOCKER_API_TOKEN"]) == 48                                            # added


def test_rerunning_keeps_the_generated_secrets(tmp_path):
    env = tmp_path / ".env"
    env.write_text("LLM_BASE_URL=u\nLLM_MODEL=m\nLLM_API_KEY=k\n")
    assert run(env).returncode == 0
    first = values(env)
    assert run(env).returncode == 0
    assert values(env) == first


def test_the_documented_dev_storage_secret_is_never_kept(tmp_path):
    env = tmp_path / ".env"
    env.write_text("LLM_BASE_URL=u\nLLM_MODEL=m\nLLM_API_KEY=k\nMINILOCKER_S3_SECRET_KEY=minilocker-dev-secret-change-me\n")
    assert run(env).returncode == 0
    assert values(env)["MINILOCKER_S3_SECRET_KEY"] != "minilocker-dev-secret-change-me"


def test_a_value_with_special_characters_survives_the_rewrite(tmp_path):
    env = tmp_path / ".env"
    env.write_text("LLM_BASE_URL=https://x/v1?a=b&c=d\nLLM_MODEL=m\nLLM_API_KEY=k/with+odd=chars&\n")
    assert run(env).returncode == 0
    v = values(env)
    assert v["LLM_BASE_URL"] == "https://x/v1?a=b&c=d" and v["LLM_API_KEY"] == "k/with+odd=chars&"


def test_unknown_options_are_rejected(tmp_path):
    r = subprocess.run(["bash", str(SCRIPT), "--bogus"], capture_output=True, text=True)
    assert r.returncode == 2 and "unknown option" in r.stderr


def test_a_setting_glued_onto_the_previous_line_is_refused_without_leaking_the_value(tmp_path):
    env = tmp_path / ".env"
    # what `echo HTTP_PORT=8080 >> .env` does to a file with no trailing newline
    env.write_text("LLM_BASE_URL=https://x/v1\nLLM_MODEL=m\nLLM_API_KEY=gsk_SUPERSECRET123HTTP_PORT=8080")
    r = run(env)
    assert r.returncode == 2
    assert "line 3" in r.stderr and "LLM_API_KEY" in r.stderr and "glued" in r.stderr
    assert "SUPERSECRET" not in r.stderr and "SUPERSECRET" not in r.stdout        # never print values
    assert "printf '\\nKEY=value\\n'" in r.stderr                                  # and says how to do it right


@pytest.mark.parametrize("line", [
    "LLM_BASE_URL=https://api.example.com/v1?mode=a&b=c",        # '=' inside a URL is normal
    "MINILOCKER_ALLOW=pypi.org,wikipedia.org",
    "LLM_API_KEY=abc=def==",                                     # base64-ish keys end in '='
    "SITE_ADDRESS=:80",
])
def test_legitimate_values_are_not_mistaken_for_glue(tmp_path, line):
    env = tmp_path / ".env"
    env.write_text(f"LLM_BASE_URL=u\nLLM_MODEL=m\nLLM_API_KEY=k\n{line}\n")
    assert run(env).returncode == 0


def test_a_clean_append_is_fine(tmp_path):
    env = tmp_path / ".env"
    env.write_text("LLM_BASE_URL=u\nLLM_MODEL=m\nLLM_API_KEY=k")        # no trailing newline
    env.write_text(env.read_text() + "\nHTTP_PORT=8080\n")              # the safe way to append
    assert run(env).returncode == 0
