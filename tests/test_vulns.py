import json
from unittest import mock

from cybersweeper import vulns
from cybersweeper.models import Host, Port, severity_from_cvss

NVD_SAMPLE = {
    "resultsPerPage": 2, "totalResults": 2,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2023-38408", "published": "2023-07-20T03:15:00.000",
            "descriptions": [{"lang": "en", "value": "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
        }},
        {"cve": {
            "id": "CVE-2021-41617", "published": "2021-09-26T19:15:00.000",
            "descriptions": [{"lang": "es", "value": "..."}, {"lang": "en", "value": "sshd in OpenSSH 6.2 through 8.7 fails to initialize supplemental groups."}],
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.4}}]},
        }},
    ],
}


def test_severity_from_cvss():
    assert severity_from_cvss(None) == "UNKNOWN"
    assert severity_from_cvss(9.8) == "CRITICAL"
    assert severity_from_cvss(7.0) == "HIGH"
    assert severity_from_cvss(5.5) == "MEDIUM"
    assert severity_from_cvss(1.0) == "LOW"
    assert severity_from_cvss(0.0) == "INFO"


def test_parse_nvd_response_sorted_by_score():
    result = vulns.parse_nvd_response(NVD_SAMPLE)
    assert [v.cve_id for v in result] == ["CVE-2023-38408", "CVE-2021-41617"]
    assert result[0].severity == "CRITICAL" and result[0].cvss_score == 9.8
    assert result[1].summary.startswith("sshd in OpenSSH")
    assert result[0].url.endswith("CVE-2023-38408") and result[0].published == "2023-07-20"


def test_rule_findings():
    assert [v.cve_id for v in vulns.rule_findings(Port(number=23, service="telnet"))] == ["CS-RULE-001"]
    assert vulns.rule_findings(Port(number=6379, service="redis"))[0].severity == "CRITICAL"
    assert vulns.rule_findings(Port(number=23, service="telnet", state="closed")) == []
    assert vulns.rule_findings(Port(number=54321, service="unknown")) == []


def test_make_query_strips_version_noise():
    assert vulns.NVDClient.make_query("OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6") == "OpenSSH 8.9"
    assert vulns.NVDClient.make_query("nginx", "1.24.0") == "nginx 1.24.0"
    assert vulns.NVDClient.make_query("Apache httpd", "") == "Apache httpd"
    assert vulns.NVDClient.make_query("vsftpd", "v3.0.5") == "vsftpd 3.0.5"


def test_cve_cache_roundtrip_and_expiry(tmp_path):
    cache = vulns.CVECache(tmp_path / "c.json", ttl_days=7)
    assert cache.get("x") is None
    cache.put("x", [{"a": 1}])
    cache.save()
    again = vulns.CVECache(tmp_path / "c.json", ttl_days=7)
    assert again.get("x") == [{"a": 1}]
    # expired entry
    data = json.loads((tmp_path / "c.json").read_text())
    data["x"]["fetched"] = "2000-01-01T00:00:00"
    (tmp_path / "c.json").write_text(json.dumps(data))
    assert vulns.CVECache(tmp_path / "c.json").get("x") is None


def _client_with_response(tmp_path, status=200, payload=None, exc=None):
    session = mock.MagicMock()
    if exc:
        session.get.side_effect = exc
    else:
        resp = mock.MagicMock(status_code=status)
        resp.json.return_value = payload or NVD_SAMPLE
        resp.raise_for_status.return_value = None
        session.get.return_value = resp
    client = vulns.NVDClient(api_key="", cache=vulns.CVECache(tmp_path / "cache.json"), session=session)
    client._throttle = lambda: None  # no sleeping in tests
    return client, session


def test_nvd_client_search_uses_cache_on_second_call(tmp_path):
    client, session = _client_with_response(tmp_path)
    first = client.search("OpenSSH", "8.9p1")
    second = client.search("OpenSSH", "8.9p1")
    assert [v.cve_id for v in first] == ["CVE-2023-38408", "CVE-2021-41617"]
    assert first[0].cve_id == second[0].cve_id
    assert session.get.call_count == 1
    params = session.get.call_args.kwargs["params"]
    assert params["keywordSearch"] == "OpenSSH 8.9"


def test_nvd_client_skips_generic_products(tmp_path):
    client, session = _client_with_response(tmp_path)
    assert client.search("HTTP server", "") == []
    assert client.search("", "1.0") == []
    session.get.assert_not_called()


def test_nvd_client_network_error_is_soft(tmp_path):
    client, _ = _client_with_response(tmp_path, exc=ConnectionError("offline"))
    assert client.search("nginx", "1.24.0") == []
    assert client.errors and "nginx 1.24.0" in client.errors[0]


def test_nvd_client_offline_mode(tmp_path):
    client, session = _client_with_response(tmp_path)
    client.offline = True
    assert client.search("nginx", "1.24.0") == []
    session.get.assert_not_called()


def test_nvd_client_sends_api_key_header(tmp_path):
    client, session = _client_with_response(tmp_path)
    client.api_key = "secret"
    client.search("nginx", "1.24.0")
    assert session.get.call_args.kwargs["headers"]["apiKey"] == "secret"


def test_assess_host_combines_rules_and_cves(tmp_path):
    client, _ = _client_with_response(tmp_path)
    host = Host(ip="10.0.0.1", ports=[
        Port(number=22, state="open", service="ssh", product="OpenSSH", version="8.9p1"),
        Port(number=23, state="open", service="telnet", product="Telnet"),
        Port(number=80, state="closed", service="http"),
    ])
    vulns.assess_host(host, client=client)
    assert [v.cve_id for v in host.ports[0].vulnerabilities] == ["CVE-2023-38408", "CVE-2021-41617"]
    assert host.ports[1].vulnerabilities[0].cve_id == "CS-RULE-001"
    assert host.ports[2].vulnerabilities == []
    assert host.max_severity == "CRITICAL"


def test_assess_host_without_client_only_rules():
    host = Host(ip="10.0.0.1", ports=[Port(number=21, state="open", service="ftp", product="vsFTPd", version="3")])
    vulns.assess_host(host, client=None)
    assert [v.source for v in host.vulnerabilities] == ["rule"]


def test_rejected_cves_are_never_reported():
    """A withdrawn CVE has no score and nothing to patch - it is not a finding."""
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2007-4044", "vulnStatus": "Rejected",
                 "descriptions": [{"lang": "en", "value": "Rejected reason: This candidate was withdrawn."}]}},
        {"cve": {"id": "CVE-2009-0001", "vulnStatus": "Analyzed",
                 "descriptions": [{"lang": "en", "value": "A real overflow."}],
                 "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}}},
    ]}

    found = vulns.parse_nvd_response(payload)

    assert [v.cve_id for v in found] == ["CVE-2009-0001"]


def test_rejected_is_detected_from_the_description_when_status_is_absent():
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2000-1234",
        "descriptions": [{"lang": "en", "value": "  Rejected reason: duplicate of CVE-2000-1111."}]}}]}
    assert vulns.parse_nvd_response(payload) == []


def test_long_cve_summaries_are_cut_at_a_word_boundary():
    long_text = "word " * 200
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2020-1", "descriptions": [{"lang": "en", "value": long_text}]}}]}

    summary = vulns.parse_nvd_response(payload)[0].summary

    assert len(summary) <= 503 and summary.endswith("...")
    assert not summary.rstrip(".").endswith("wor")  # no half-word like "even this li"
