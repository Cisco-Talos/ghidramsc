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

"""Configuration loading for GhidraMSC.

Searches for ``ghidramsc.toml`` in the following order:
  1. Path given via ``GHIDRAMSC_CONFIG`` environment variable
  2. Current working directory
  3. GhidraMSC repository root (parent of this package)

The TOML file must contain a ``[ghidramsc]`` section.  Example::

    [ghidramsc]
    ghidra_install_dir = "C:/tools/ghidra_12.1.4_PUBLIC"
    project_path = "C:/projects/my_ghidra/projects"
    project_name = "MyProject"
    # server_port = 13100  # optional, default 13100

Any key can be overridden by an environment variable with the prefix
``GHIDRAMSC_``.  For instance ``GHIDRAMSC_GHIDRA_INSTALL_DIR`` overrides
``ghidra_install_dir``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Minimal TOML parser (stdlib tomllib is 3.11+; the package supports 3.10+).
# Only handles flat key = "value" pairs inside a named section.
# ---------------------------------------------------------------------------

def _parse_toml_section(path: Path, section: str = "ghidramsc") -> Dict[str, str]:
    """Return key/value pairs from *section* in a TOML file."""
    data: Dict[str, str] = {}
    in_section = False
    with open(path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                in_section = line.strip("[] ").lower() == section.lower()
                continue
            if in_section and "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                data[key] = val
    return data


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

class GhidraMSCConfig:
    """Resolved configuration for a GhidraMSC session."""

    def __init__(
        self,
        ghidra_install_dir: str,
        project_path: str,
        project_name: str,
        server_port: Optional[str] = None,
    ) -> None:
        self.ghidra_install_dir = Path(ghidra_install_dir)
        self.project_path = Path(project_path)
        self.project_name = project_name

        # Server port (default 13100).
        self.server_port = int(server_port) if server_port else 13100

    def validate(self) -> None:
        """Raise if critical paths are missing."""
        if not self.ghidra_install_dir.exists():
            raise FileNotFoundError(
                "Ghidra installation not found: {}".format(self.ghidra_install_dir)
            )
        if not self.project_path.exists():
            raise FileNotFoundError(
                "Ghidra project directory not found: {}".format(self.project_path)
            )


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

_SEARCH_KEYS = [
    "ghidra_install_dir",
    "project_path",
    "project_name",
    "server_port",
]


def _find_config_file() -> Optional[Path]:
    """Locate ghidramsc.toml using the search order described in the module
    docstring."""
    env = os.environ.get("GHIDRAMSC_CONFIG")
    if env:
        p = Path(env)
        if p.is_file():
            return p

    cwd = Path.cwd() / "ghidramsc.toml"
    if cwd.is_file():
        return cwd

    repo = Path(__file__).resolve().parent.parent / "ghidramsc.toml"
    if repo.is_file():
        return repo

    return None


def load_config(config_path: Optional[str] = None) -> GhidraMSCConfig:
    """Load and return a `GhidraMSCConfig`.

    Parameters
    ----------
    config_path : str, optional
        Explicit path to a TOML config file.  If ``None``, the standard
        search order is used.
    """
    file_data: Dict[str, str] = {}
    path = Path(config_path) if config_path else _find_config_file()
    if path and path.is_file():
        file_data = _parse_toml_section(path)

    # Environment overrides
    merged: Dict[str, Any] = {}
    for key in _SEARCH_KEYS:
        env_val = os.environ.get("GHIDRAMSC_" + key.upper())
        if env_val:
            merged[key] = env_val
        elif key in file_data:
            merged[key] = file_data[key]

    # Mandatory keys
    for req in ("ghidra_install_dir", "project_path", "project_name"):
        if req not in merged:
            raise ValueError(
                "Missing required config key '{}'. "
                "Set it in ghidramsc.toml or via GHIDRAMSC_{} env var.".format(
                    req, req.upper()
                )
            )

    return GhidraMSCConfig(**merged)
