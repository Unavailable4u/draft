"""The .env loader. No Docker. Uses throwaway environ dicts, never the real environment."""
import pytest

from minilocker.config import find_env_file, load_env, parse


def test_parse_the_formats_people_actually_write():
    text = ('\ufeff# comment\n\nLLM_BASE_URL=https://api.groq.com/openai/v1\r\n'
            'export LLM_MODEL = openai/gpt-oss-120b  # model\n'
            'LLM_API_KEY="gsk_abc#def"\n'
            "QUOTED='with spaces'\nEMPTY=\nnot a setting\n=novalue\n1BAD=x\n")
    assert parse(text) == {
        "LLM_BASE_URL": "https://api.groq.com/openai/v1",     # \r from Windows editors is gone
        "LLM_MODEL": "openai/gpt-oss-120b",                   # inline comment stripped
        "LLM_API_KEY": "gsk_abc#def",                         # '#' inside quotes is part of the value
        "QUOTED": "with spaces", "EMPTY": ""}


def test_real_environment_wins_and_empty_counts_as_unset(tmp_path):
    (tmp_path / ".env").write_text("A=file\nB=file\nC=file\n")
    env = {"A": "shell", "B": ""}
    path, applied = load_env(env, start=tmp_path)
    assert env == {"A": "shell", "B": "file", "C": "file"} and applied == 2 and path.name == ".env"


def test_finds_deploy_env_walking_up_from_backend(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / ".env").write_text("LLM_MODEL=m\n")
    backend = tmp_path / "backend"
    backend.mkdir()
    env = {}
    assert load_env(env, start=backend)[0] == tmp_path / "deploy" / ".env" and env == {"LLM_MODEL": "m"}


def test_nearest_directory_wins_and_no_file_is_fine(tmp_path):
    (tmp_path / ".env").write_text("X=outer\n")
    inner = tmp_path / "a"
    inner.mkdir()
    (inner / ".env").write_text("X=inner\n")
    env = {}
    load_env(env, start=inner)
    assert env["X"] == "inner"
    empty = tmp_path / "x" / "y"
    empty.mkdir(parents=True)
    other = tmp_path.parent / "no-env-here"
    other.mkdir(exist_ok=True)
    assert load_env({}, start=other) is None


def test_explicit_file_wins_and_a_missing_one_is_an_error(tmp_path):
    (tmp_path / ".env").write_text("X=cwd\n")
    custom = tmp_path / "custom.env"
    custom.write_text("X=custom\n")
    env = {"MINILOCKER_ENV_FILE": str(custom)}
    load_env(env, start=tmp_path)
    assert env["X"] == "custom"
    with pytest.raises(FileNotFoundError):
        find_env_file({"MINILOCKER_ENV_FILE": str(tmp_path / "nope.env")})


def test_values_are_never_printed(tmp_path, capsys, monkeypatch):
    from minilocker import config
    (tmp_path / ".env").write_text("LLM_API_KEY=sekrit-value-123\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLM_API_KEY", "")     # empty counts as unset; monkeypatch restores it afterwards
    config.load_and_report()
    out = capsys.readouterr().out
    assert "1 setting(s) loaded" in out and "sekrit" not in out


def test_the_previous_test_left_nothing_in_the_real_environment():
    import os
    assert "sekrit" not in os.environ.get("LLM_API_KEY", "")
