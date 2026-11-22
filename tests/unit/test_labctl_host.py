"""labctl.py on a plain headless Linux host: Docker resolution, settings from .env, the model
credential rule, compose overlays, and the doctor's verdicts. No Docker needed."""
import pytest

import labctl


@pytest.fixture()
def linux_host(monkeypatch, tmp_path):
    """docker on PATH, no wsl.exe — a remote Linux VM."""
    monkeypatch.setattr(labctl.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    monkeypatch.setattr(labctl, "ROOT", tmp_path)
    for var in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "LAB_KVM", "LAB_LANGFUSE_UI", "WSLENV",
                "DEFENDER_DRIVER"):
        monkeypatch.delenv(var, raising=False)
    labctl._KVM = None
    yield tmp_path
    labctl._KVM = None


def write_env(root, text):
    (root / ".env").write_text(text, encoding="utf-8")


def test_linux_uses_docker_directly_and_never_wsl(linux_host):
    assert labctl.docker_prefix() == ["docker"]
    assert not labctl.using_wsl()
    assert "WSLENV" not in labctl.docker_env()


def test_missing_docker_on_linux_points_at_host_setup(monkeypatch, linux_host):
    monkeypatch.setattr(labctl.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit) as exc:
        labctl.docker_prefix()
    assert "scripts/host-setup.sh" in str(exc.value)


def test_dotenv_parsing(linux_host):
    write_env(linux_host, "# c\nA=1\nexport B='two'\nC=\"three\"\n\nbroken line\n")
    assert labctl.read_dotenv() == {"A": "1", "B": "two", "C": "three"}


@pytest.mark.parametrize("env,expected", [
    ({}, "none"), ({"ANTHROPIC_API_KEY": "k"}, "api_key"), ({"CLAUDE_CODE_OAUTH_TOKEN": "t"}, "oauth"),
    ({"ANTHROPIC_API_KEY": "k", "CLAUDE_CODE_OAUTH_TOKEN": "t"}, "conflict"),
    ({"ANTHROPIC_API_KEY": "", "CLAUDE_CODE_OAUTH_TOKEN": "t"}, "oauth"),
])
def test_defender_auth(env, expected):
    assert labctl.defender_auth(env) == expected


def test_oauth_token_means_no_api_key_reaches_compose(linux_host):
    write_env(linux_host, "ANTHROPIC_API_KEY=\nCLAUDE_CODE_OAUTH_TOKEN=sk-fake-oauth\n")
    env = labctl.docker_env()
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "sk-fake-oauth"
    assert "ANTHROPIC_API_KEY" not in env


def test_api_key_mode_passes_only_the_key(linux_host, monkeypatch):
    write_env(linux_host, "ANTHROPIC_API_KEY=fake-key\n")
    env = labctl.docker_env()
    assert env["ANTHROPIC_API_KEY"] == "fake-key" and "CLAUDE_CODE_OAUTH_TOKEN" not in env


def test_both_credentials_pass_neither(linux_host, monkeypatch):
    write_env(linux_host, "ANTHROPIC_API_KEY=fake-key\n")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-oauth")        # the shell adds the other one
    env = labctl.docker_env()
    assert "ANTHROPIC_API_KEY" not in env and "CLAUDE_CODE_OAUTH_TOKEN" not in env


def test_shell_environment_overrides_dotenv(linux_host, monkeypatch):
    write_env(linux_host, "TARGET_MEMORY_MB=4096\n")
    monkeypatch.setenv("TARGET_MEMORY_MB", "8192")
    assert labctl.docker_env()["TARGET_MEMORY_MB"] == "8192"
    assert labctl.settings()["TARGET_MEMORY_MB"] == "8192"


def test_overlays_follow_kvm_and_the_langfuse_opt_in(linux_host, monkeypatch):
    monkeypatch.setattr(labctl, "host_has_kvm", lambda: True)
    assert labctl.compose_files() == ["compose.yaml", "compose.kvm.yaml"]
    labctl._KVM = None
    write_env(linux_host, "LAB_KVM=0\nLAB_LANGFUSE_UI=1\n")
    assert labctl.compose_files() == ["compose.yaml", "compose.langfuse-ui.yaml"]
    labctl._KVM = None
    monkeypatch.setattr(labctl, "host_has_kvm", lambda: False)
    write_env(linux_host, "")
    assert labctl.compose_files() == ["compose.yaml"]
    assert labctl.compose_cmd("ps")[:6] == ["docker", "compose", "-f", "compose.yaml", "--env-file", ".lab/lab.env"]


def test_resource_verdicts():
    gib = 1024 ** 3
    big = dict((item, status) for status, item, _ in labctl.assess_resources(16, 64 * gib, 500 * gib))
    assert big == {"cpus": "ok", "memory": "ok", "disk": "ok"}
    small = dict((item, status) for status, item, _ in labctl.assess_resources(4, 8 * gib, 20 * gib))
    assert small == {"cpus": "WARN", "memory": "WARN", "disk": "WARN"}


@pytest.mark.parametrize("host_kvm,disabled,active,status,word", [
    (True, False, "kvm", "ok", "ACTIVE"),
    (True, False, None, "ok", "will use KVM"),
    (False, False, None, "WARN", "TCG software emulation"),
    (False, False, "tcg", "WARN", "NOT active"),
    (True, True, "tcg", "WARN", "LAB_KVM=0"),
])
def test_kvm_verdict_is_explicit(host_kvm, disabled, active, status, word):
    got_status, detail = labctl.kvm_verdict(host_kvm, disabled, 0, active)
    assert got_status == status and word in detail
    if status == "WARN":
        assert "long-horizon runs want a KVM-capable host" in detail


def test_nftables_verdict_prefers_the_functional_test():
    assert labctl.nftables_verdict("unknown", "", True)[0] == "ok"
    assert labctl.nftables_verdict("loaded", "y", False)[0] == "FAIL"
    assert labctl.nftables_verdict("unknown", "m", None)[0] == "ok"
    assert labctl.nftables_verdict("unknown", "", None)[0] == "WARN"



def test_doctor_checks_the_users_segment_and_identities():
    import yaml
    doc = yaml.safe_load((labctl.ROOT / "compose.yaml").read_text(encoding="utf-8"))
    assert labctl.users_segment_verdict(doc)[0] == "ok"
    broken = {**doc, "services": {**doc["services"], "defender": {**doc["services"]["defender"],
                                                                   "networks": {"users_seg": {}}}}}
    assert labctl.users_segment_verdict(broken)[0] == "FAIL"
    assert labctl.identities_verdict({"10.20.3.30": ["probe", "ok"]})[0] == "ok"
    assert labctl.identities_verdict({"10.20.3.30": ["probe", "TimeoutError"]})[0] == "FAIL"
