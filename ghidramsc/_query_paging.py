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

"""Finite, deterministic inspection-page metadata shared by query families."""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple


def validate_page(offset: int, limit: int, *, label: str = "page",
                  maximum: int = 500) -> None:
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("{} offset must be non-negative".format(label))
    if (not isinstance(limit, int) or isinstance(limit, bool)
            or limit < 1 or limit > maximum):
        raise ValueError("{} limit must be 1..{}".format(label, maximum))


def page_metadata(offset: int, limit: int, returned: int,
                  total: int) -> Dict[str, Any]:
    next_offset = offset + returned
    has_more = next_offset < total
    return {
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "total": total,
        "has_more": has_more,
        "next_offset": next_offset if has_more else None,
    }


def page_items(items: Sequence[Any], offset: int, limit: int
               ) -> Tuple[List[Any], Dict[str, Any]]:
    selected = list(items[offset:offset + limit])
    return selected, page_metadata(offset, limit, len(selected), len(items))
