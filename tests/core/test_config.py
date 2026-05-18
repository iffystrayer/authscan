"""Tests for configuration management."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from auth_scan.core.config import (
    ScanConfig,
    generate_default_config,
    load_config,
)
from auth_scan.core.exceptions import ConfigError


class TestScanConfig:
    """Tests for the ScanConfig dataclass."""

    def test_default_values(self) -> None:
        config = ScanConfig()
        assert config.rate_limit == 10
        assert config.timeout == 30
        assert config.output_formats == ["terminal"]
        assert config.modules == ["probe", "jwt", "session", "brute"]

    def test_validate_rate_limit_too_low(self) -> None:
        config = ScanConfig(rate_limit=0)
        with pytest.raises(ConfigError, match="rate_limit"):
            config.validate()

    def test_validate_rate_limit_too_high(self) -> None:
        config = ScanConfig(rate_limit=200)
        with pytest.raises(ConfigError, match="rate_limit"):
            config.validate()

    def test_validate_timeout(self) -> None:
        config = ScanConfig(timeout=0)
        with pytest.raises(ConfigError, match="timeout"):
            config.validate()

    def test_validate_auth_type(self) -> None:
        config = ScanConfig(auth_type="invalid")
        with pytest.raises(ConfigError, match="auth_type"):
            config.validate()

    def test_validate_output_formats(self) -> None:
        config = ScanConfig(output_formats=["invalid_format"])
        with pytest.raises(ConfigError, match="output format"):
            config.validate()

    def test_valid_config_passes(self) -> None:
        config = ScanConfig(
            target="https://example.com",
            rate_limit=10,
            timeout=30,
            auth_type="bearer",
            output_formats=["terminal", "json"],
        )
        config.validate()  # Should not raise


class TestConfigLoading:
    """Tests for config loading from file."""

    def test_load_from_yaml_file(self, config_file: Path) -> None:
        config = load_config(config_path=str(config_file))
        assert config.rate_limit == 5
        assert config.modules == ["probe", "jwt"]

    def test_load_missing_file(self) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_config(config_path="/nonexistent/path.yml")

    def test_load_with_profile(self, tmp_path: Path) -> None:
        import yaml

        config_data = {
            "rate_limit": 10,
            "profiles": {
                "slow": {"rate_limit": 3},
                "fast": {"rate_limit": 50},
            },
        }
        path = tmp_path / "profiled-config.yml"
        path.write_text(yaml.dump(config_data))
        config = load_config(config_path=str(path), profile="slow")
        assert config.rate_limit == 3

    def test_load_with_invalid_profile(self, tmp_path: Path) -> None:
        import yaml

        config_data = {
            "rate_limit": 10,
            "profiles": {"slow": {"rate_limit": 3}},
        }
        path = tmp_path / "config.yml"
        path.write_text(yaml.dump(config_data))
        with pytest.raises(ConfigError, match="Profile"):
            load_config(config_path=str(path), profile="nonexistent")

    def test_env_var_override(self, tmp_path: Path) -> None:
        import yaml

        config_data = {"rate_limit": 10}
        path = tmp_path / "config.yml"
        path.write_text(yaml.dump(config_data))

        os.environ["AUTH_SCAN_RATE_LIMIT"] = "5"
        try:
            config = load_config(config_path=str(path))
            assert config.rate_limit == 5
        finally:
            del os.environ["AUTH_SCAN_RATE_LIMIT"]

    def test_env_var_boolean(self, tmp_path: Path) -> None:
        import yaml

        config_data = {"no_verify": False}
        path = tmp_path / "config.yml"
        path.write_text(yaml.dump(config_data))

        os.environ["AUTH_SCAN_NO_VERIFY"] = "true"
        try:
            config = load_config(config_path=str(path))
            assert config.no_verify is True
        finally:
            del os.environ["AUTH_SCAN_NO_VERIFY"]


class TestConfigGeneration:
    """Tests for --init config generation."""

    def test_generate_default_config(self, tmp_path: Path) -> None:
        output = tmp_path / "auth-scan-config.yml"
        path = generate_default_config(str(output))
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "rate_limit" in content
        assert "# auth-scan configuration file" in content

    def test_generated_config_is_loadable(self, tmp_path: Path) -> None:
        output = tmp_path / "auth-scan-config.yml"
        path = generate_default_config(str(output))
        config = load_config(config_path=str(path))
        assert config.rate_limit == 10


class TestCLIOverrides:
    """Tests for merging CLI overrides into config."""

    def test_merge_rate_limit(self) -> None:
        config = ScanConfig(rate_limit=10)
        config.merge_cli_overrides(rate_limit=5)
        assert config.rate_limit == 5

    def test_merge_does_not_override_with_defaults(self) -> None:
        config = ScanConfig(rate_limit=10)
        config.merge_cli_overrides(timeout=30)  # 30 is default
        # timeout should stay at default
        assert config.timeout == 30
