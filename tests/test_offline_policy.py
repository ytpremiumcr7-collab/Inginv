from pathlib import Path

from inginv.offline_policy import scan_python_source, scan_python_tree


def test_product_source_contains_no_network_transport_or_resolver_imports():
    root = Path(__file__).resolve().parents[1]
    findings = scan_python_tree(root / "src")
    assert findings == []


def test_detects_http_client_import():
    findings = scan_python_source("bad.py", "import http.client\n")
    assert findings[0].rule == "NETWORK_IMPORT"
    assert findings[0].detail == "http.client"


def test_detects_literal_curl_subprocess():
    findings = scan_python_source(
        "bad.py",
        "import subprocess\nsubprocess.run(['curl', 'https://example.invalid'])\n",
    )
    assert findings[0].rule == "NETWORK_SUBPROCESS"
    assert findings[0].detail == "curl"


def test_url_parsing_remains_allowed_for_offline_static_analysis():
    findings = scan_python_source("ok.py", "from urllib.parse import urlsplit\n")
    assert findings == []
