import pytest

from cybersweep import config, utils


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
