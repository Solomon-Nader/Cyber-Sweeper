import json
from unittest import mock

from cybersweeper import cli, netinfo

WIN_JSON = json.dumps([
    {"alias": "Ethernet", "ip": "10.0.0.7", "prefix": 16, "gateway": "10.0.0.1",
     "mac": "AA-BB-CC-00-00-01", "media": "802.3", "desc": "Realtek PCIe GbE Family Controller",
     "profile": "Network 3", "status": "Up"},
    {"alias": "Wi-Fi", "ip": "192.168.1.23", "prefix": 24, "gateway": "192.168.1.1",
     "mac": "AA-BB-CC-00-00-02", "media": "Native 802.11", "desc": "Intel(R) Wi-Fi 6 AX201",
     "profile": "HomeNet-5G", "status": "Up"},
])

LINUX_ROUTE = json.dumps([{"dst": "default", "gateway": "192.168.1.1", "dev": "wlan0", "protocol": "dhcp"}])
LINUX_ADDR = json.dumps([{"ifname": "wlan0", "addr_info": [
    {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
    {"family": "inet", "local": "192.168.1.42", "prefixlen": 24, "scope": "global"},
]}])


# --------------------------------------------------------------------------- #
# NetworkInfo
# --------------------------------------------------------------------------- #


def test_networkinfo_cidr_and_description():
    net = netinfo.NetworkInfo(connected=True, kind="wifi", ssid="HomeNet", interface="Wi-Fi",
                              ip="192.168.1.23", prefix=24, gateway="192.168.1.1")
    assert net.cidr == "192.168.1.0/24"
    assert net.host_count == 254
    text = net.describe()
    assert "Wi-Fi 'HomeNet'" in text and "192.168.1.0/24" in text and "gateway 192.168.1.1" in text
    assert net.to_dict()["cidr"] == "192.168.1.0/24"


def test_networkinfo_offline():
    net = netinfo.NetworkInfo()
    assert net.connected is False and net.cidr == "" and net.host_count == 0
    assert net.describe().startswith("Not connected")


# --------------------------------------------------------------------------- #
# Windows parser
# --------------------------------------------------------------------------- #


def test_parse_windows_prefers_interface_matching_local_ip():
    net = netinfo.parse_windows_json(WIN_JSON, local_ip="192.168.1.23")
    assert net.connected and net.kind == "wifi" and net.ssid == "HomeNet-5G"
    assert net.interface == "Wi-Fi" and net.prefix == 24 and net.gateway == "192.168.1.1"
    assert net.mac == "AA:BB:CC:00:00:02"
    assert net.cidr == "192.168.1.0/24"


def test_parse_windows_ethernet_has_no_ssid():
    net = netinfo.parse_windows_json(WIN_JSON, local_ip="10.0.0.7")
    assert net.kind == "ethernet" and net.ssid == "" and net.cidr == "10.0.0.0/16"


def test_parse_windows_single_object_and_garbage():
    single = json.dumps({"alias": "Wi-Fi", "ip": "172.16.5.9", "prefix": 20, "gateway": "172.16.0.1",
                         "media": "Native 802.11", "profile": "Office"})
    assert netinfo.parse_windows_json(single).cidr == "172.16.0.0/20"
    assert netinfo.parse_windows_json("") is None
    assert netinfo.parse_windows_json("not json") is None
    assert netinfo.parse_windows_json("[]") is None


# --------------------------------------------------------------------------- #
# Linux parser
# --------------------------------------------------------------------------- #


def test_parse_linux_wifi():
    net = netinfo.parse_linux(LINUX_ROUTE, LINUX_ADDR, wireless=True, ssid="CafeWifi", mac="de:ad:be:ef:00:01")
    assert net.kind == "wifi" and net.ssid == "CafeWifi" and net.interface == "wlan0"
    assert net.ip == "192.168.1.42" and net.prefix == 24 and net.gateway == "192.168.1.1"


def test_parse_linux_ethernet_ignores_ssid():
    net = netinfo.parse_linux(LINUX_ROUTE, LINUX_ADDR, wireless=False, ssid="ignored")
    assert net.kind == "ethernet" and net.ssid == ""


def test_parse_linux_no_default_route():
    assert netinfo.parse_linux("[]", LINUX_ADDR, False) is None
    assert netinfo.parse_linux("garbage", LINUX_ADDR, False) is None
    assert netinfo.parse_linux(LINUX_ROUTE, "[]", False) is None


# --------------------------------------------------------------------------- #
# detect_network orchestration
# --------------------------------------------------------------------------- #


def test_detect_network_uses_platform_detector(monkeypatch):
    monkeypatch.setattr(netinfo.platform, "system", lambda: "Windows")
    monkeypatch.setattr(netinfo, "primary_ip", lambda: "192.168.1.23")
    monkeypatch.setattr(netinfo, "_detect_windows",
                        lambda ip: netinfo.parse_windows_json(WIN_JSON, ip))
    net = netinfo.detect_network()
    assert net.kind == "wifi" and net.cidr == "192.168.1.0/24"


def test_detect_network_falls_back_to_udp_route(monkeypatch):
    monkeypatch.setattr(netinfo.platform, "system", lambda: "Linux")
    monkeypatch.setattr(netinfo, "primary_ip", lambda: "10.1.2.3")
    monkeypatch.setattr(netinfo, "_detect_linux", lambda ip: None)
    net = netinfo.detect_network()
    assert net.connected and net.cidr == "10.1.2.0/24" and net.method == "fallback/udp-route"
    assert net.notes


def test_detect_network_offline(monkeypatch):
    monkeypatch.setattr(netinfo.platform, "system", lambda: "Linux")
    monkeypatch.setattr(netinfo, "primary_ip", lambda: "")
    monkeypatch.setattr(netinfo, "_detect_linux", lambda ip: None)
    net = netinfo.detect_network()
    assert net.connected is False


def test_detect_network_swallows_detector_errors(monkeypatch):
    monkeypatch.setattr(netinfo.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(netinfo, "primary_ip", lambda: "192.168.7.7")
    monkeypatch.setattr(netinfo, "_detect_macos", mock.Mock(side_effect=RuntimeError("boom")))
    assert netinfo.detect_network().cidr == "192.168.7.0/24"


def test_run_handles_missing_binary():
    assert netinfo._run(["definitely-not-a-real-command-xyz"]) == ""


# --------------------------------------------------------------------------- #
# CLI integration
# --------------------------------------------------------------------------- #

WIFI = netinfo.NetworkInfo(connected=True, kind="wifi", ssid="HomeNet", interface="Wi-Fi",
                           ip="192.168.1.23", prefix=24, gateway="192.168.1.1", method="test")
OFFLINE = netinfo.NetworkInfo(connected=False)


def test_cli_network_command(monkeypatch, capsys):
    monkeypatch.setattr(cli.netinfo, "detect_network", lambda: WIFI)
    assert cli.main(["network"]) == 0
    out = capsys.readouterr().out
    assert "HomeNet" in out and "192.168.1.0/24" in out and "Wi-Fi" in out
    assert cli.main(["network", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["cidr"] == "192.168.1.0/24"


def test_cli_network_offline_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(cli.netinfo, "detect_network", lambda: OFFLINE)
    assert cli.main(["network"]) == 1
    assert "Not connected" in capsys.readouterr().out


def test_cli_scan_without_target_uses_detected_network(monkeypatch, capsys):
    monkeypatch.setattr(cli.netinfo, "detect_network", lambda: WIFI)
    captured = {}

    class FakeEngine:
        def __init__(self, opts, progress=None):
            captured["target"] = opts.target

        def run(self):
            from cybersweeper.models import ScanResult
            return ScanResult(options=__import__("cybersweeper.models", fromlist=["ScanOptions"]).ScanOptions(
                target=captured["target"]), engine="socket")

    monkeypatch.setattr(cli, "ScanEngine", FakeEngine)
    assert cli.main(["--no-banner", "scan", "--no-save"]) == 0
    out = capsys.readouterr().out
    assert captured["target"] == "192.168.1.0/24"
    assert "auto target: 192.168.1.0/24" in out
    assert "target auto-detected" in out


def test_cli_scan_without_target_when_offline(monkeypatch, capsys):
    monkeypatch.setattr(cli.netinfo, "detect_network", lambda: OFFLINE)
    assert cli.main(["--no-banner", "scan"]) == 2
    assert "not appear to be connected" in capsys.readouterr().err


def test_cli_discover_without_target(monkeypatch, capsys):
    monkeypatch.setattr(cli.netinfo, "detect_network", lambda: WIFI)
    monkeypatch.setattr(cli.discovery, "discover_hosts", lambda ips, **kw: ([], "tcp"))
    assert cli.main(["--no-banner", "discover"]) == 0
    assert "192.168.1.0/24 (254 addresses)" in capsys.readouterr().out


def test_cli_check_includes_network(monkeypatch, capsys):
    monkeypatch.setattr(cli.netinfo, "detect_network", lambda: WIFI)
    assert cli.main(["check"]) == 0
    assert "network" in capsys.readouterr().out
