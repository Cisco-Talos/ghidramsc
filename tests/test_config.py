# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for ghidramsc.config -- TOML parsing, env overrides, validation."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest import mock

import pytest

from ghidramsc.config import (
    GhidraMSCConfig,
    _parse_toml_section,
    load_config,
)


# ---------------------------------------------------------------------------
# _parse_toml_section
# ---------------------------------------------------------------------------

class TestParseTomlSection:
    def test_basic(self, tmp_path):
        f = tmp_path / "test.toml"
        f.write_text(textwrap.dedent("""\
            [ghidramsc]
            ghidra_install_dir = "C:/tools/ghidra"
            project_path = "C:/projects"
            project_name = "TestProject"
        """))
        data = _parse_toml_section(f)
        assert data["ghidra_install_dir"] == "C:/tools/ghidra"
        assert data["project_path"] == "C:/projects"
        assert data["project_name"] == "TestProject"

    def test_ignores_other_sections(self, tmp_path):
        f = tmp_path / "test.toml"
        f.write_text(textwrap.dedent("""\
            [other]
            key = "nope"

            [ghidramsc]
            project_name = "Yes"
        """))
        data = _parse_toml_section(f)
        assert "key" not in data
        assert data["project_name"] == "Yes"

    def test_comments_and_blanks(self, tmp_path):
        f = tmp_path / "test.toml"
        f.write_text(textwrap.dedent("""\
            # top comment

            [ghidramsc]
            # inline comment
            project_name = "Hello"

        """))
        data = _parse_toml_section(f)
        assert data["project_name"] == "Hello"

    def test_single_quotes(self, tmp_path):
        f = tmp_path / "test.toml"
        f.write_text(textwrap.dedent("""\
            [ghidramsc]
            project_name = 'SingleQ'
        """))
        data = _parse_toml_section(f)
        assert data["project_name"] == "SingleQ"

    def test_empty_file(self, tmp_path):
        f = tmp_path / "test.toml"
        f.write_text("")
        data = _parse_toml_section(f)
        assert data == {}


# ---------------------------------------------------------------------------
# GhidraMSCConfig
# ---------------------------------------------------------------------------

class TestGhidraMSCConfig:
    def test_defaults(self, tmp_path):
        cfg = GhidraMSCConfig(
            ghidra_install_dir=str(tmp_path),
            project_path=str(tmp_path),
            project_name="Test",
        )
        assert cfg.ghidra_install_dir == tmp_path
        assert cfg.project_name == "Test"

    def test_validate_ghidra_missing(self, tmp_path):
        cfg = GhidraMSCConfig(
            ghidra_install_dir=str(tmp_path / "nonexistent"),
            project_path=str(tmp_path),
            project_name="Test",
        )
        with pytest.raises(FileNotFoundError, match="Ghidra installation"):
            cfg.validate()

    def test_validate_project_missing(self, tmp_path):
        cfg = GhidraMSCConfig(
            ghidra_install_dir=str(tmp_path),
            project_path=str(tmp_path / "nonexistent"),
            project_name="Test",
        )
        with pytest.raises(FileNotFoundError, match="project directory"):
            cfg.validate()

    def test_validate_ok(self, tmp_path):
        cfg = GhidraMSCConfig(
            ghidra_install_dir=str(tmp_path),
            project_path=str(tmp_path),
            project_name="Test",
        )
        cfg.validate()  # should not raise


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_explicit_path(self, tmp_path):
        f = tmp_path / "my.toml"
        f.write_text(textwrap.dedent("""\
            [ghidramsc]
            ghidra_install_dir = "{gdir}"
            project_path = "{pdir}"
            project_name = "Explicit"
        """.format(gdir=str(tmp_path).replace("\\", "/"),
                   pdir=str(tmp_path).replace("\\", "/"))))
        cfg = load_config(str(f))
        assert cfg.project_name == "Explicit"

    def test_removed_output_path_is_ignored(self, tmp_path):
        f = tmp_path / "legacy.toml"
        f.write_text(textwrap.dedent("""\
            [ghidramsc]
            ghidra_install_dir = "{gdir}"
            project_path = "{pdir}"
            project_name = "Legacy"
            output_path = "C:/unused"
        """.format(gdir=str(tmp_path).replace("\\", "/"),
                   pdir=str(tmp_path).replace("\\", "/"))))
        cfg = load_config(str(f))
        assert not hasattr(cfg, "output_path")

    def test_env_overrides(self, tmp_path):
        f = tmp_path / "my.toml"
        f.write_text(textwrap.dedent("""\
            [ghidramsc]
            ghidra_install_dir = "/original"
            project_path = "/original"
            project_name = "FromFile"
        """))
        env = {"GHIDRAMSC_PROJECT_NAME": "FromEnv"}
        with mock.patch.dict(os.environ, env, clear=False):
            cfg = load_config(str(f))
        assert cfg.project_name == "FromEnv"

    def test_missing_required_key(self, tmp_path):
        f = tmp_path / "my.toml"
        f.write_text(textwrap.dedent("""\
            [ghidramsc]
            ghidra_install_dir = "/something"
        """))
        with pytest.raises(ValueError, match="Missing required config key"):
            load_config(str(f))

    def test_env_only(self, tmp_path):
        env = {
            "GHIDRAMSC_GHIDRA_INSTALL_DIR": str(tmp_path),
            "GHIDRAMSC_PROJECT_PATH": str(tmp_path),
            "GHIDRAMSC_PROJECT_NAME": "EnvOnly",
        }
        # Point config search away from any real config file
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("ghidramsc.config._find_config_file", return_value=None):
                cfg = load_config()
        assert cfg.project_name == "EnvOnly"

    def test_env_config_path(self, tmp_path):
        f = tmp_path / "special.toml"
        f.write_text(textwrap.dedent("""\
            [ghidramsc]
            ghidra_install_dir = "/g"
            project_path = "/p"
            project_name = "EnvPath"
        """))
        env = {"GHIDRAMSC_CONFIG": str(f)}
        with mock.patch.dict(os.environ, env, clear=False):
            cfg = load_config()
        assert cfg.project_name == "EnvPath"
