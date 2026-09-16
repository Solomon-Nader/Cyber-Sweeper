import pytest

from cybersweeper import config, utils


class TestParseTargets:
    def test_single_ip(self):
        assert utils.parse_targets("192.168.1.10") == ["192.168.1.10"]

    def test_cidr_excludes_network_and_broadcast(self):
        ips = utils.parse_targets("10.0.0.0/30")
        assert ips == ["10.0.0.1", "10.0.0.2"]

    def test_cidr_24_size(self):
        assert len(utils.parse_targets("10.0.0.0/24")) == 254

    def test_last_octet_range(self):
        assert utils.parse_targets("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]

    def test_full_range(self):
        ips = utils.parse_targets("10.0.0.254-10.0.1.1")
        assert ips == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]

    def test_comma_list_dedup_and_order(self):
        assert utils.parse_targets("10.0.0.2, 10.0.0.1,10.0.0.2") == ["10.0.0.2", "10.0.0.1"]

    def test_localhost_resolves(self):
        assert utils.parse_targets("localhost") == ["127.0.0.1"]

    @pytest.mark.parametrize("bad", ["", "   ", "10.0.0.300", "10.0.0.0/33", "10.0.0.9-5",
                                     "abc.def.ghi", "10.0.0.1-999", "::1"])
    def test_invalid(self, bad):
        with pytest.raises(utils.TargetError):
            utils.parse_targets(bad)

    def test_max_hosts_guard(self):
        with pytest.raises(utils.TargetError):
            utils.parse_targets("10.0.0.0/16", max_hosts=100)


class TestParsePorts:
    def test_default_is_top100(self):
        assert utils.parse_ports(None) == config.TOP_100_PORTS
        assert utils.parse_ports("") == config.TOP_100_PORTS

    def test_presets(self):
        assert utils.parse_ports("common") == config.COMMON_PORTS
        assert utils.parse_ports("ALL")[-1] == 65535 and len(utils.parse_ports("all")) == 65535

    def test_mixed(self):
        assert utils.parse_ports("80, 22,443-445") == [22, 80, 443, 444, 445]

    def test_preset_inside_list(self):
        ports = utils.parse_ports("common,9999")
        assert 9999 in ports and 22 in ports

    @pytest.mark.parametrize("bad", ["0", "70000", "80-", "a-b", "10-5", "x"])
    def test_invalid(self, bad):
        with pytest.raises(utils.PortError):
            utils.parse_ports(bad)


def test_ports_to_spec_roundtrip():
    spec = utils.ports_to_spec([22, 80, 81, 82, 443, 8080])
    assert spec == "22,80-82,443,8080"
    assert utils.parse_ports(spec) == [22, 80, 81, 82, 443, 8080]
    assert utils.ports_to_spec([]) == ""


def test_human_duration():
    assert utils.human_duration(3.14) == "3.1s"
    assert utils.human_duration(125) == "2m 5s"
    assert utils.human_duration(3700) == "1h 1m"


def test_local_network_cidr_is_valid():
    import ipaddress

    ipaddress.ip_network(utils.local_network_cidr())


def test_data_dir_honours_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSWEEPER_HOME", str(tmp_path / "explicit"))
    assert config.data_dir() == tmp_path / "explicit"
    assert config.default_db_path().name == "cybersweeper.db"


# The 2.0.0 rename must not strand scan history saved as ~/.cybersweep.
def test_data_dir_migrates_pre_2_0_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERSWEEPER_HOME", raising=False)
    monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))
    legacy = tmp_path / ".cybersweep"
    legacy.mkdir()
    (legacy / "cybersweep.db").write_bytes(b"old scans")
    (legacy / "cve_cache.json").write_text("{}")

    path = config.data_dir()

    assert path == tmp_path / ".cybersweeper" and not legacy.exists()
    assert config.default_db_path().read_bytes() == b"old scans"
    assert (path / "cve_cache.json").exists()


def test_data_dir_leaves_an_existing_new_directory_alone(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERSWEEPER_HOME", raising=False)
    monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))
    (tmp_path / ".cybersweep").mkdir()
    (tmp_path / ".cybersweep" / "cybersweep.db").write_bytes(b"old")
    new = tmp_path / ".cybersweeper"
    new.mkdir()
    (new / "cybersweeper.db").write_bytes(b"current")

    assert config.data_dir() == new
    assert config.default_db_path().read_bytes() == b"current"
    assert (tmp_path / ".cybersweep").exists()  # untouched, not deleted


def test_truncate_words_never_splits_a_word():
    text = "Multiple heap-based buffer overflows in the NDR parsing in smbd"
    assert utils.truncate_words(text, 40) == "Multiple heap-based buffer overflows..."
    assert utils.truncate_words(text, 500) == text
    assert utils.truncate_words("  spaced   out  ", 100) == "spaced out"
    assert utils.truncate_words("", 10) == ""
    assert utils.truncate_words("a" * 30, 10) == "a" * 10 + "..."  # no break available


def test_is_precise_version_accepts_real_builds_and_rejects_ranges():
    for precise in ("8.9p1", "1.1.4", "2017.75", "5.4.0-150-generic", "0.9.8zh"):
        assert utils.is_precise_version(precise), precise
    for vague in ("3.X - 4.X", "2.0.8 or later", "1.14.0 or later", "10.x",
                  "3.0 through 3.2", "before 2.0", "", None, "unknown"):
        assert not utils.is_precise_version(vague), vague
