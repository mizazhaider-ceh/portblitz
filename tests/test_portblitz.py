"""
PortBlitz v5.0 — Comprehensive Test Suite

Tests for scanner, service detection, CVE lookup, report generation,
bridge safety, network parsing, export, and false-positive detection.

Run:  python -m pytest tests/test_portblitz.py -v
"""

import asyncio
import html as _html
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===================================================================
# 1. Scanner — scan_port
# ===================================================================

class TestScanPort:
    """Unit tests for core.scanner.scan_port."""

    @pytest.mark.asyncio
    async def test_open_port(self):
        """scan_port returns (port, True) when connection succeeds."""
        from core.scanner import scan_port

        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (MagicMock(), mock_writer)
            port, is_open = await scan_port("127.0.0.1", 80, timeout=0.5)

        assert port == 80
        assert is_open is True

    @pytest.mark.asyncio
    async def test_closed_port_timeout(self):
        """scan_port returns (port, False) on timeout."""
        from core.scanner import scan_port

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError()
            port, is_open = await scan_port("127.0.0.1", 9999, timeout=0.1)

        assert port == 9999
        assert is_open is False

    @pytest.mark.asyncio
    async def test_closed_port_refused(self):
        """scan_port returns (port, False) on ConnectionRefusedError."""
        from core.scanner import scan_port

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError()
            port, is_open = await scan_port("127.0.0.1", 12345, timeout=0.1)

        assert port == 12345
        assert is_open is False

    @pytest.mark.asyncio
    async def test_closed_port_os_error(self):
        """scan_port handles OSError gracefully."""
        from core.scanner import scan_port

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = OSError("Network unreachable")
            port, is_open = await scan_port("10.0.0.1", 22, timeout=0.1)

        assert is_open is False


# ===================================================================
# 2. Scanner — CDN / WAF False-Positive Detection
# ===================================================================

class TestFalsePositiveDetection:
    """Tests for the canary-port based CDN/WAF detection in scanner.py."""

    @pytest.mark.asyncio
    async def test_detects_cdn_catch_all(self):
        """detect_false_positives returns True when most canary ports accept TCP."""
        from core.scanner import detect_false_positives

        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mc:
            mc.return_value = (MagicMock(), mock_writer)
            result = await detect_false_positives("cdn-host.example.com", timeout=0.1, quiet=True)

        assert result is True

    @pytest.mark.asyncio
    async def test_clean_target_passes(self):
        """detect_false_positives returns False when canary ports are closed."""
        from core.scanner import detect_false_positives

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mc:
            mc.side_effect = ConnectionRefusedError()
            result = await detect_false_positives("clean-host.example.com", timeout=0.1, quiet=True)

        assert result is False

    @pytest.mark.asyncio
    async def test_partial_canaries_below_threshold(self):
        """detect_false_positives returns False when <75% canary ports are open."""
        from core.scanner import detect_false_positives

        call_count = 0

        async def mixed_connection(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:  # Only 3 of 8 open
                mock_w = MagicMock()
                mock_w.close = MagicMock()
                mock_w.wait_closed = AsyncMock()
                return (MagicMock(), mock_w)
            raise ConnectionRefusedError()

        with patch("core.scanner.asyncio.open_connection", side_effect=mixed_connection):
            result = await detect_false_positives("partial.example.com", timeout=0.1, quiet=True)

        assert result is False


# ===================================================================
# 3. Scanner — verify_port
# ===================================================================

class TestVerifyPort:
    """Tests for the secondary banner-verification of open ports."""

    @pytest.mark.asyncio
    async def test_verify_with_banner_data(self):
        """verify_port returns True when the port sends back data."""
        from core.scanner import verify_port

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.drain = AsyncMock()

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mc:
            mc.return_value = (mock_reader, mock_writer)
            result = await verify_port("example.com", 8080, timeout=0.5)

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_no_data_well_known_port(self):
        """verify_port returns True for well-known port even without data."""
        from core.scanner import verify_port

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.drain = AsyncMock()

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mc:
            mc.return_value = (mock_reader, mock_writer)
            result = await verify_port("example.com", 80, timeout=0.5)

        assert result is True  # port 80 is well-known

    @pytest.mark.asyncio
    async def test_verify_no_data_unknown_port(self):
        """verify_port returns False for non-well-known port without data."""
        from core.scanner import verify_port

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.drain = AsyncMock()

        with patch("core.scanner.asyncio.open_connection", new_callable=AsyncMock) as mc:
            mc.return_value = (mock_reader, mock_writer)
            result = await verify_port("example.com", 47293, timeout=0.5)

        assert result is False  # random port, no data → false positive


# ===================================================================
# 4. Service Detection
# ===================================================================

class TestServiceDetection:
    """Tests for core.service.detect_service."""

    def test_detect_http_apache(self):
        from core.service import detect_service
        assert detect_service("HTTP/1.1 200 OK\r\nServer: Apache/2.4.51") == "http"

    def test_detect_http_nginx(self):
        from core.service import detect_service
        assert detect_service("HTTP/1.1 301 Moved\r\nServer: Nginx") == "http"

    def test_detect_ssh(self):
        from core.service import detect_service
        assert detect_service("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3") == "ssh"

    def test_detect_ftp(self):
        from core.service import detect_service
        assert detect_service("220 vsftpd 3.0.3 FTP ready") == "ftp"

    def test_detect_smtp(self):
        from core.service import detect_service
        assert detect_service("220 mail.example.com ESMTP Postfix") == "smtp"

    def test_detect_mysql(self):
        from core.service import detect_service
        assert detect_service("5.7.38-MariaDB") == "mysql"

    def test_detect_redis(self):
        from core.service import detect_service
        assert detect_service("-ERR redis_version:6.2.6") == "redis"

    def test_empty_banner_returns_guess(self):
        from core.service import detect_service
        assert detect_service("", "http") == "http"

    def test_unknown_banner(self):
        from core.service import detect_service
        assert detect_service("CUSTOM_BINARY_PROTOCOL_V1", "unknown") == "unknown"

    def test_cloudflare_detected_as_http(self):
        from core.service import detect_service
        assert detect_service("HTTP/1.1 403 Forbidden\r\nServer: Cloudflare") == "http"


# ===================================================================
# 5. CVE Lookup
# ===================================================================

class TestCVELookup:
    """Tests for utils.cve.lookup_cves."""

    def test_apache_path_traversal(self):
        from utils.cve import lookup_cves
        cves = lookup_cves("Server: Apache/2.4.49")
        assert any("CVE-2021-41773" in c for c in cves)

    def test_vsftpd_backdoor(self):
        from utils.cve import lookup_cves
        cves = lookup_cves("220 vsFTPd 2.3.4 ready")
        assert any("CVE-2011-2523" in c for c in cves)

    def test_heartbleed(self):
        from utils.cve import lookup_cves
        cves = lookup_cves("OpenSSL 1.0.1f")
        assert any("Heartbleed" in c for c in cves)

    def test_no_match(self):
        from utils.cve import lookup_cves
        assert lookup_cves("Totally-Unknown-Server/99.0") == []

    def test_empty_banner(self):
        from utils.cve import lookup_cves
        assert lookup_cves("") == []

    def test_none_banner(self):
        from utils.cve import lookup_cves
        assert lookup_cves(None) == []


# ===================================================================
# 6. Network / Target Parsing
# ===================================================================

class TestNetParsing:
    """Tests for utils.net.parse_targets and load_targets_from_file."""

    def test_single_ip(self):
        from utils.net import parse_targets
        assert parse_targets("192.168.1.1") == ["192.168.1.1"]

    def test_domain(self):
        from utils.net import parse_targets
        assert parse_targets("example.com") == ["example.com"]

    def test_cidr_24(self):
        from utils.net import parse_targets
        hosts = parse_targets("10.0.0.0/30")
        # /30 = 2 usable hosts
        assert len(hosts) == 2
        assert "10.0.0.1" in hosts
        assert "10.0.0.2" in hosts

    def test_cidr_single_host(self):
        from utils.net import parse_targets
        hosts = parse_targets("10.0.0.5/32")
        # /32 = 0 usable hosts from .hosts() but single IP
        assert len(hosts) == 0 or hosts == ["10.0.0.5"]

    def test_load_targets_from_file(self):
        from utils.net import load_targets_from_file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment line\n")
            f.write("192.168.1.1\n")
            f.write("\n")
            f.write("10.0.0.1\n")
            f.write("example.com\n")
            f.name
        try:
            targets = load_targets_from_file(f.name)
            assert "192.168.1.1" in targets
            assert "10.0.0.1" in targets
            assert "example.com" in targets
        finally:
            os.unlink(f.name)

    def test_load_targets_file_not_found(self):
        from utils.net import load_targets_from_file
        with pytest.raises(FileNotFoundError):
            load_targets_from_file("/nonexistent/path/targets.txt")


# ===================================================================
# 7. HTML Report — XSS Safety
# ===================================================================

class TestReportXSSSafety:
    """Verify that HTML reports escape user-controlled data."""

    def test_target_xss_escaped(self):
        from utils.report import generate_report
        malicious_target = '<script>alert("xss")</script>'
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_report(malicious_target, [], output_dir=tmpdir)
            assert Path(path).exists(), "Report file was not created"
            content = Path(path).read_text(encoding="utf-8")

        # The raw <script> tag must NOT appear; the escaped form must be present
        assert "<script>alert" not in content
        assert "&lt;script&gt;" in content

    def test_banner_xss_escaped(self):
        from utils.report import generate_report
        results = [{
            "port": 80,
            "service": "http",
            "banner": '<img src=x onerror=alert(1)>',
        }]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_report("safe-host", results, output_dir=tmpdir)
            content = Path(path).read_text(encoding="utf-8")

        # Raw <img> tag must be escaped — browser won't execute it
        assert '<img src=x' not in content
        assert '&lt;img' in content

    def test_service_xss_escaped(self):
        from utils.report import generate_report
        results = [{
            "port": 22,
            "service": '"><svg/onload=alert(1)>',
            "banner": "SSH-2.0-Test",
        }]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_report("host", results, output_dir=tmpdir)
            content = Path(path).read_text(encoding="utf-8")

        # Raw <svg> tag must not appear; escaped form should
        assert '<svg/' not in content
        assert '&lt;svg' in content

    def test_report_creates_file(self):
        from utils.report import generate_report
        results = [{"port": 80, "service": "http", "banner": "OK"}]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_report("10.0.0.1", results, output_dir=tmpdir)
            assert Path(path).exists()
            assert Path(path).stat().st_size > 100


# ===================================================================
# 8. Tool Bridge — Command Injection Prevention
# ===================================================================

class TestBridgeSafety:
    """Verify that the tool bridge blocks unsafe inputs."""

    def test_safe_target_passes_validation(self):
        from modules.bridge import _validate
        assert _validate("192.168.1.1", "target") == "192.168.1.1"
        assert _validate("example.com", "target") == "example.com"
        assert _validate("10.0.0.0/24", "target") == "10.0.0.0/24"

    def test_shell_metachar_blocked(self):
        from modules.bridge import _validate
        with pytest.raises(ValueError):
            _validate("192.168.1.1; rm -rf /", "target")

    def test_pipe_blocked(self):
        from modules.bridge import _validate
        with pytest.raises(ValueError):
            _validate("target | cat /etc/passwd", "target")

    def test_backtick_blocked(self):
        from modules.bridge import _validate
        with pytest.raises(ValueError):
            _validate("`whoami`", "target")

    def test_dollar_expansion_blocked(self):
        from modules.bridge import _validate
        with pytest.raises(ValueError):
            _validate("$(id)", "target")

    def test_nmap_not_installed(self):
        from modules.bridge import ToolBridge
        with patch("modules.bridge.shutil.which", return_value=None):
            result = asyncio.get_event_loop().run_until_complete(
                ToolBridge.run_nmap_version("127.0.0.1", 80)
            )
        assert result == "Nmap not installed"

    def test_nuclei_not_installed(self):
        from modules.bridge import ToolBridge
        with patch("modules.bridge.shutil.which", return_value=None):
            result = asyncio.get_event_loop().run_until_complete(
                ToolBridge.run_nuclei("127.0.0.1", 80)
            )
        assert result == "Nuclei not installed"


# ===================================================================
# 9. JSON / CSV Export
# ===================================================================

class TestExport:
    """Tests for utils.export JSON and CSV export functions."""

    def test_json_export(self):
        from utils.export import export_json
        data = {"target": "10.0.0.1", "results": [{"port": 80, "service": "http"}]}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = export_json(data, tmpdir)
            content = json.loads(Path(path).read_text())
            assert content["target"] == "10.0.0.1"
            assert content["results"][0]["port"] == 80

    def test_csv_export(self):
        from utils.export import export_csv
        data = {
            "target": "10.0.0.1",
            "results": [{"port": 80, "service": "http", "banner": "Apache"}],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = export_csv(data, tmpdir)
            lines = Path(path).read_text().strip().split("\n")
            assert len(lines) == 2  # header + 1 row
            assert "80" in lines[1]

    def test_csv_empty_results(self):
        from utils.export import export_csv
        data = {"target": "10.0.0.1", "results": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_csv(data, tmpdir)
            assert result is None


# ===================================================================
# 10. Display & Version
# ===================================================================

class TestDisplay:
    """Tests for utils.display module."""

    def test_version_string(self):
        from utils.display import VERSION
        assert VERSION == "5.0"

    def test_colors_have_reset(self):
        from utils.display import Colors
        assert Colors.RESET == "\033[0m"

    def test_print_banner_runs(self, capsys):
        from utils.display import print_banner
        print_banner()
        captured = capsys.readouterr()
        # Banner uses spaced-out letters: "P O R T B L I T Z"
        assert "P O R T B L I T Z" in captured.out or "PortBlitz" in captured.out


# ===================================================================
# 11. CLI Argument Parsing
# ===================================================================

class TestCLIArgs:
    """Smoke tests for CLI argument parsing in portblitz.py."""

    def test_help_flag(self):
        """--help should exit with code 0."""
        import subprocess
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "portblitz.py"), "--help"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
        )
        assert result.returncode == 0
        assert "PortBlitz" in result.stdout

    def test_no_args_exits_with_error(self):
        """Running without target or -i should print usage."""
        import subprocess
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "portblitz.py")],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
        )
        assert result.returncode != 0 or "No targets" in result.stdout


# ===================================================================
# 12. Console / TUI
# ===================================================================

class TestConsole:
    """Tests for core.console.PortBlitzConsole."""

    def test_set_target(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_set("target 192.168.1.1")
        assert console.target_str == "192.168.1.1"
        assert len(console.target_list) == 1

    def test_set_ports(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_set("ports 1-1000")
        assert console.ports_str == "1-1000"

    def test_set_vuln_on(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_set("vuln on")
        assert console.options.vuln is True

    def test_set_vuln_off(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_set("vuln on")
        console.do_set("vuln off")
        assert console.options.vuln is False

    def test_show_runs(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_show("")
        captured = capsys.readouterr()
        assert "SESSION" in captured.out or "Target" in captured.out

    def test_help_runs(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_help("")
        captured = capsys.readouterr()
        assert "set" in captured.out
        assert "run" in captured.out

    def test_exit_returns_true(self):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        assert console.do_exit("") is True

    def test_set_rate(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_set("rate 500")
        assert console.options.rate == 500

    def test_set_unknown_option(self, capsys):
        from core.console import PortBlitzConsole
        console = PortBlitzConsole()
        console.do_set("foobar value")
        captured = capsys.readouterr()
        assert "Unknown" in captured.out


# ===================================================================
# 13. Live Host Discovery
# ===================================================================

class TestLiveHost:
    """Tests for core.live.is_host_up."""

    @pytest.mark.asyncio
    async def test_host_up_tcp(self):
        from core.live import is_host_up

        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("core.live.asyncio.open_connection", new_callable=AsyncMock) as mc:
            mc.return_value = (MagicMock(), mock_writer)
            result = await is_host_up("192.168.1.1", timeout=0.5)

        assert result is True

    @pytest.mark.asyncio
    async def test_host_down(self):
        from core.live import is_host_up

        with patch("core.live.asyncio.open_connection", new_callable=AsyncMock) as mc:
            mc.side_effect = ConnectionRefusedError()
            with patch("core.live.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_ping:
                mock_proc = MagicMock()
                mock_proc.returncode = 1
                mock_proc.wait = AsyncMock()
                mock_ping.return_value = mock_proc
                result = await is_host_up("10.255.255.1", timeout=0.1)

        assert result is False
