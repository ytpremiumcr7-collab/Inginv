from pathlib import Path
import socket

import pytest

from inginv.offline_policy import (
    scan_python_source,
    scan_python_tree,
    scan_repository_source,
)


def test_product_source_contains_no_network_transport_or_resolver_imports():
    root = Path(__file__).resolve().parents[1]
    findings = scan_python_tree(root / "src")
    assert findings == []


@pytest.mark.parametrize(
    "source",
    [
        "import requests\n",
        "import socket\n",
        "from urllib.request import urlopen\n",
        "import paho.mqtt.client\n",
        "import dns.resolver\n",
    ],
)
def test_detects_network_imports(source):
    findings = scan_python_source("bad.py", source)
    assert findings
    assert findings[0].rule == "NETWORK_IMPORT"


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            "import subprocess\nsubprocess.run(['curl', 'https://example.invalid'])\n",
            "curl",
        ),
        (
            "import subprocess\nsubprocess.run(['bash', '-lc', 'wget https://example.invalid'])\n",
            "wget",
        ),
        (
            "import subprocess\nsubprocess.Popen('mosquitto_sub -h example.invalid', shell=True)\n",
            "mosquitto_sub",
        ),
    ],
)
def test_detects_literal_network_subprocess(source, expected):
    findings = scan_python_source("bad.py", source)
    assert any(
        finding.rule == "NETWORK_SUBPROCESS" and finding.detail == expected
        for finding in findings
    )


def test_url_parsing_remains_allowed_for_offline_static_analysis():
    findings = scan_python_source(
        "ok.py",
        "from urllib.parse import urlsplit\nvalue = urlsplit('https://example.invalid/path')\n",
    )
    assert findings == []


def test_test_suite_network_fixture_blocks_dns_and_socket_connections():
    with pytest.raises(AssertionError, match="network access is disabled"):
        socket.getaddrinfo("example.invalid", 443)
    with pytest.raises(AssertionError, match="network access is disabled"):
        socket.create_connection(("127.0.0.1", 9))


def test_repository_source_guard_is_clean():
    root = Path(__file__).resolve().parents[1]
    report = scan_repository_source(root)
    assert report["finding_count"] == 0
