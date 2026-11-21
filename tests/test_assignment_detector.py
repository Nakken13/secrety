import pytest

import fakes
from secrety.detectors.assignment import UnquotedAssignmentDetector, is_config_file
from secrety.models import Finding

PW = fakes.ENV_PASSWORD


def _scan(text: str, path: str) -> list[Finding]:
    return list(UnquotedAssignmentDetector().scan(text, path))


@pytest.mark.parametrize(
    "path",
    [".env", ".env.production", "conf/app.ini", "deploy.yml", "k8s/values.yaml", "a.properties"],
)
def test_config_files_are_recognised(path: str) -> None:
    assert is_config_file(path)


@pytest.mark.parametrize("path", ["app.py", "main.js", "README.md", "environment.py"])
def test_code_files_are_not_config_files(path: str) -> None:
    assert not is_config_file(path)


@pytest.mark.parametrize(
    ("path", "line"),
    [
        (".env", f"DB_PASSWORD={PW}"),
        (".env", f"export API_KEY={PW}"),
        (".env.local", f"SECRET_KEY = {PW}  # rotated monthly"),
        ("config.yml", f"  password: {PW}"),
        ("app.ini", f"auth_token : {PW}"),
        ("docker-compose.yml", f"      - DB_PASSWORD={PW}"),
        ("config.yaml", f"  - password: {PW}"),
    ],
)
def test_unquoted_secret_in_config_file_is_flagged(path: str, line: str) -> None:
    [finding] = _scan(f"# header\n{line}\n", path)
    assert finding.rule_id == "generic-password-unquoted"
    assert finding.secret == PW
    assert (finding.line, finding.column) == (2, line.index(PW) + 1)


@pytest.mark.parametrize(
    "line",
    [
        "password=${DB_PASSWORD}",
        "password: <your-password>",
        "password: {{ vault_password }}",
        "password: %(db_password)s",
        "password: short",
        'password: "quoted-is-left-to-the-regex-rule"',
        "# password: commented-out-line",
        "password_policy_url: x",
    ],
)
def test_references_placeholders_and_short_values_are_ignored(line: str) -> None:
    assert _scan(line, ".env") == []


def test_code_files_are_not_scanned() -> None:
    # In code an unquoted value is an identifier or a call, not a literal.
    assert _scan("password = get_password_from_vault()", "app.py") == []
