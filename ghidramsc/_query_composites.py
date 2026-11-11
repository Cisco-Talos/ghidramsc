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

"""Private composites implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .bridge import ProgramContext

from ._query_core import (
    _end_mutation_transaction,
    _get_monitor,
    _java_isinstance,
    _mutation_no_change,
    _mutation_validation_failure,
    _qualified_program_name,
    _resolve_type,
    _run_mutation_transaction,
    _start_mutation_transaction,
)


def list_structures(ctx: ProgramContext) -> str:
    """List all defined structure data types."""
    from ghidra.program.model.data import Structure  # type: ignore
    dtm = ctx.program.getDataTypeManager()
    structs = []
    for dt in dtm.getAllDataTypes():
        if _java_isinstance(dt, Structure, "getComponentContaining"):
            try:
                n = dt.getNumComponents()
                structs.append({
                    "name": dt.getName(),
                    "path": str(dt.getCategoryPath()),
                    "size": dt.getLength(),
                    "num_fields": n,
                })
            except Exception:
                pass

    structs.sort(key=lambda s: s["name"])
    lines = ["STRUCTURES in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), len(structs))]
    for s in structs:
        lines.append("  {} ({} bytes, {} fields)  {}".format(
            s["name"], s["size"], s["num_fields"], s["path"]))
    return "\n".join(lines)


def _find_structure(ctx: ProgramContext, name: str,
                    category_path: str = "") -> Any:
    from ghidra.program.model.data import Structure  # type: ignore

    matches = []
    for candidate in ctx.program.getDataTypeManager().getAllDataTypes():
        if (candidate.getName() == name
                and _java_isinstance(
                    candidate, Structure, "getComponentContaining")):
            if (category_path and str(candidate.getCategoryPath()) != category_path):
                continue
            matches.append(candidate)
    if len(matches) > 1:
        paths = sorted(str(item.getCategoryPath()) for item in matches)
        raise ValueError(
            "Structure '{}' is ambiguous; specify category_path (matches: {})".format(
                name, ", ".join(paths)
            )
        )
    return matches[0] if matches else None


def get_structure(ctx: ProgramContext, name: str,
                  category_path: str = "") -> Dict[str, Any]:
    """Get full details of a structure: fields, offsets, types, sizes."""
    try:
        dt = _find_structure(ctx, name, category_path)
    except ValueError as exc:
        return {"error": str(exc)}

    if dt is None:
        where = " in {}".format(category_path) if category_path else ""
        return {"error": "Structure '{}' not found{}".format(name, where)}

    fields = []
    for i in range(dt.getNumComponents()):
        comp = dt.getComponent(i)
        fields.append({
            "ordinal": i,
            "offset": comp.getOffset(),
            "name": comp.getFieldName() or "",
            "type": str(comp.getDataType().getName()),
            "size": comp.getLength(),
            "comment": comp.getComment() or "",
        })

    return {
        "name": dt.getName(),
        "path": str(dt.getCategoryPath()),
        "size": dt.getLength(),
        "num_fields": dt.getNumComponents(),
        "num_defined_fields": dt.getNumDefinedComponents(),
        "packing_enabled": bool(dt.isPackingEnabled()),
        "packing": ("explicit" if dt.hasExplicitPackingValue() else
                    "default" if dt.hasDefaultPacking() else "disabled"),
        "packing_value": (dt.getExplicitPackingValue()
                          if dt.hasExplicitPackingValue() else 0),
        "alignment": dt.getAlignment(),
        "alignment_mode": ("machine" if dt.isMachineAligned() else
                           "explicit" if dt.hasExplicitMinimumAlignment()
                           else "default"),
        "minimum_alignment": (dt.getExplicitMinimumAlignment()
                              if dt.hasExplicitMinimumAlignment() else 0),
        "fields": fields,
    }


def _find_composite(ctx: ProgramContext, name: str,
                    category_path: str = "") -> Any:
    matches = []
    for candidate in ctx.program.getDataTypeManager().getAllDataTypes():
        if (candidate.getName() == name
                and hasattr(candidate, "getNumComponents")):
            if (category_path
                    and str(candidate.getCategoryPath()) != category_path):
                continue
            matches.append(candidate)
    if len(matches) > 1:
        paths = sorted(str(item.getCategoryPath()) for item in matches)
        raise ValueError(
            "Composite '{}' is ambiguous; specify category_path "
            "(matches: {})".format(name, ", ".join(paths))
        )
    return matches[0] if matches else None


def get_composite(ctx: ProgramContext, name: str,
                  category_path: str = "") -> Dict[str, Any]:
    """Read an exact structure or union, including bitfield metadata."""
    from ghidra.program.model.data import BitFieldDataType, Union  # type: ignore

    try:
        composite = _find_composite(ctx, name, category_path)
    except ValueError as exc:
        return {"error": str(exc)}
    if composite is None:
        where = " in {}".format(category_path) if category_path else ""
        return {"error": "Composite '{}' not found{}".format(name, where)}
    fields = []
    for component in list(composite.getComponents()):
        data_type = component.getDataType()
        field = {
            "ordinal": component.getOrdinal(),
            "offset": component.getOffset(),
            "end_offset": component.getEndOffset(),
            "name": component.getFieldName() or "",
            "type": str(data_type.getName()),
            "display_type": str(data_type.getDisplayName()),
            "size": component.getLength(),
            "comment": component.getComment() or "",
            "is_bitfield": bool(component.isBitFieldComponent()),
            "is_zero_bitfield": bool(component.isZeroBitFieldComponent()),
        }
        if isinstance(data_type, BitFieldDataType):
            field.update({
                "base_type": str(data_type.getBaseDataType().getName()),
                "bit_size": data_type.getBitSize(),
                "declared_bit_size": data_type.getDeclaredBitSize(),
                "bit_offset": data_type.getBitOffset(),
                "storage_size": data_type.getStorageSize(),
            })
        fields.append(field)
    return {
        "name": composite.getName(),
        "path": str(composite.getCategoryPath()),
        "kind": "union" if _java_isinstance(
            composite, Union, "insertBitField") and not hasattr(
                composite, "insertBitFieldAt") else "structure",
        "size": composite.getLength(),
        "num_fields": composite.getNumComponents(),
        "num_defined_fields": composite.getNumDefinedComponents(),
        "packing_enabled": bool(composite.isPackingEnabled()),
        "packing": (
            "explicit" if composite.hasExplicitPackingValue() else
            "default" if composite.hasDefaultPacking() else "disabled"
        ),
        "packing_value": (
            composite.getExplicitPackingValue()
            if composite.hasExplicitPackingValue() else 0
        ),
        "alignment": composite.getAlignment(),
        "alignment_mode": (
            "machine" if composite.isMachineAligned() else
            "explicit" if composite.hasExplicitMinimumAlignment()
            else "default"
        ),
        "minimum_alignment": (
            composite.getExplicitMinimumAlignment()
            if composite.hasExplicitMinimumAlignment() else 0
        ),
        "fields": fields,
    }


def create_structure(ctx: ProgramContext, name: str, size: int = 0,
                     category_path: str = "/") -> Dict[str, Any]:
    """Create a new structure data type at an exact category path."""
    from ghidra.program.model.data import (  # type: ignore
        CategoryPath, DataTypeConflictHandler, Structure, StructureDataType,
    )

    requested = {
        "name": name,
        "size": size,
        "category_path": category_path,
    }
    try:
        path = CategoryPath(category_path)
    except Exception as exc:
        return _structure_mutation_result(
            "create_structure", "validation_failed", requested, {},
            error="Invalid category path: " + str(exc),
        )

    dtm = ctx.program.getDataTypeManager()
    if dtm.getDataType(path, name) is not None:
        return _structure_mutation_result(
            "create_structure", "validation_failed", requested, {},
            error="Data type already exists at {}/{}".format(
                category_path, name
            ),
        )

    old = {
        "exists": False,
        "name": name,
        "category_path": category_path,
    }
    tx_id = _start_mutation_transaction(ctx, "Create structure")
    commit = False
    try:
        try:
            created = StructureDataType(path, name, size)
            added = dtm.addDataType(
                created, DataTypeConflictHandler.DEFAULT_HANDLER
            )
            if not _java_isinstance(
                    added, Structure, "getComponentContaining"):
                raise ValueError("Created data type is not a structure")
            if (str(added.getName()) != name
                    or str(added.getCategoryPath()) != category_path
                    or (size != 0 and int(added.getLength()) != size)):
                raise ValueError("Stored structure identity mismatch")

            stored = get_structure(ctx, name, category_path)
            if (stored.get("error")
                    or stored.get("name") != name
                    or stored.get("path") != category_path
                    or (size != 0 and stored.get("size") != size)):
                raise ValueError("Structure read-back mismatch")
            stored["exists"] = True
            commit = True
            return _structure_mutation_result(
                "create_structure", "success", requested, old, stored
            )
        except Exception as exc:
            return _structure_mutation_result(
                "create_structure", "rolled_back", requested, old,
                error=str(exc),
            )
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def _find_first_structure(ctx: ProgramContext, name: str):
    from ghidra.program.model.data import Structure  # type: ignore

    for candidate in ctx.program.getDataTypeManager().getAllDataTypes():
        if (candidate.getName() == name
                and _java_isinstance(
                    candidate, Structure, "getComponentContaining")):
            return candidate
    return None


def _structure_state_by_name(
    ctx: ProgramContext, name: str
) -> Dict[str, Any]:
    structure = _find_first_structure(ctx, name)
    if structure is None:
        return {"exists": False, "name": name}
    state = get_structure(
        ctx, name, str(structure.getCategoryPath())
    )
    if "error" in state:
        raise ValueError("get_structure read-back failed: " + state["error"])
    state["exists"] = True
    return state


def set_structure_name(ctx: ProgramContext, old_name: str,
                     new_name: str) -> Dict[str, Any]:
    """Rename the first matching structure using name-only selection."""
    requested = {"old_name": old_name, "new_name": new_name}
    old = _structure_state_by_name(ctx, old_name)
    if not old["exists"]:
        return _mutation_validation_failure(
            "set_structure_name", requested,
            "Structure '{}' not found".format(old_name),
        )
    if old_name == new_name:
        return _mutation_no_change("set_structure_name", requested, old)
    if _structure_state_by_name(ctx, new_name)["exists"]:
        return _mutation_validation_failure(
            "set_structure_name", requested,
            "Structure '{}' already exists".format(new_name),
        )
    structure = _find_first_structure(ctx, old_name)

    def validate(stored: Any) -> Optional[str]:
        if stored["exists"] and not _structure_state_by_name(
            ctx, old_name
        )["exists"]:
            return None
        return "Structure rename read-back mismatch"

    return _run_mutation_transaction(
        ctx,
        "set_structure_name",
        "Rename structure",
        requested,
        old,
        lambda: structure.setName(new_name),
        lambda: _structure_state_by_name(ctx, new_name),
        validate,
        lambda: _structure_state_by_name(ctx, old_name),
    )


def delete_structure(ctx: ProgramContext, name: str) -> Dict[str, Any]:
    """Delete the first matching structure using name-only selection."""
    requested = {"name": name, "exists": False}
    old = _structure_state_by_name(ctx, name)
    if not old["exists"]:
        return _mutation_validation_failure(
            "delete_structure", requested,
            "Structure '{}' not found".format(name),
        )
    dtm = ctx.program.getDataTypeManager()
    structure = _find_first_structure(ctx, name)

    return _run_mutation_transaction(
        ctx,
        "delete_structure",
        "Delete structure",
        requested,
        old,
        lambda: dtm.remove(structure, _get_monitor()),
        lambda: _structure_state_by_name(ctx, name),
        lambda stored: (
            None if not stored["exists"]
            else "Structure remains after deletion: " + name
        ),
    )


def _structure_mutation_result(operation: str, status: str,
                               requested: Dict[str, Any],
                               old: Dict[str, Any],
                               stored: Optional[Dict[str, Any]] = None,
                               error: str = "") -> Dict[str, Any]:
    result = {
        "operation": operation,
        "status": status,
        "requested": requested,
        "old": old,
        "transaction": {
            "started": status in ("success", "rolled_back"),
            "committed": status == "success",
        },
    }
    if stored is not None:
        result["stored"] = stored
    if error:
        result["error"] = error
    return result


def set_structure_field(ctx: ProgramContext, name: str, category_path: str,
                        offset: int, field_name: str, type_name: str,
                        mode: str = "replace", length: int = 0,
                        comment: str = "") -> Dict[str, Any]:
    """Insert or replace one structure field at an exact byte offset."""
    requested = {
        "name": name, "category_path": category_path, "offset": offset,
        "field_name": field_name, "type_name": type_name, "mode": mode,
        "length": length, "comment": comment,
    }
    try:
        structure = _find_structure(ctx, name, category_path)
    except ValueError as exc:
        return _structure_mutation_result(
            "set_structure_field", "validation_failed", requested, {},
            error=str(exc))
    if structure is None:
        return _structure_mutation_result(
            "set_structure_field", "validation_failed", requested, {},
            error="Structure '{}' not found in {}".format(name, category_path))
    if offset < 0 or mode not in ("replace", "insert"):
        return _structure_mutation_result(
            "set_structure_field", "validation_failed", requested, {},
            error="offset must be non-negative and mode replace or insert")
    containing = structure.getComponentContaining(offset)
    if (mode == "insert" and containing is not None
            and str(containing.getDataType().getName()) != "undefined"
            and containing.getOffset() < offset):
        return _structure_mutation_result(
            "set_structure_field", "validation_failed", requested, {},
            error="Insertion offset {} overlaps field '{}' at [{}, {})".format(
                offset, containing.getFieldName(), containing.getOffset(),
                containing.getEndOffset() + 1,
            ))
    data_type = _resolve_type(ctx.program, type_name)
    if data_type is None:
        return _structure_mutation_result(
            "set_structure_field", "validation_failed", requested, {},
            error="Unknown type: " + type_name)
    effective_length = length if length > 0 else data_type.getLength()
    if effective_length <= 0:
        return _structure_mutation_result(
            "set_structure_field", "validation_failed", requested, {},
            error="A positive length is required for dynamic type " + type_name)
    requested["effective_length"] = effective_length
    old = get_structure(ctx, name, category_path)
    tx_id = _start_mutation_transaction(ctx, "Edit structure field")
    commit = False
    try:
        try:
            if mode == "insert":
                component = structure.insertAtOffset(
                    offset, data_type, effective_length, field_name, comment)
            else:
                component = structure.replaceAtOffset(
                    offset, data_type, effective_length, field_name, comment)
            if (component.getOffset() != offset
                    or component.getFieldName() != field_name
                    or component.getLength() != effective_length
                    or not data_type.isEquivalent(component.getDataType())):
                raise ValueError("Structure field read-back mismatch")
            stored = get_structure(ctx, name, category_path)
            commit = True
            return _structure_mutation_result(
                "set_structure_field", "success", requested, old, stored)
        except Exception as exc:
            return _structure_mutation_result(
                "set_structure_field", "rolled_back", requested, old,
                error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def delete_structure_field(ctx: ProgramContext, name: str,
                           category_path: str,
                           offset: int) -> Dict[str, Any]:
    """Delete one defined field that starts at an exact offset."""
    requested = {
        "name": name, "category_path": category_path, "offset": offset,
    }
    try:
        structure = _find_structure(ctx, name, category_path)
    except ValueError as exc:
        return _structure_mutation_result(
            "delete_structure_field", "validation_failed", requested, {},
            error=str(exc))
    if structure is None:
        return _structure_mutation_result(
            "delete_structure_field", "validation_failed", requested, {},
            error="Structure '{}' not found in {}".format(name, category_path))
    component = structure.getComponentAt(offset)
    if (component is None or component.getOffset() != offset
            or str(component.getDataType().getName()) == "undefined"):
        return _structure_mutation_result(
            "delete_structure_field", "validation_failed", requested, {},
            error="No defined field starts at offset {}".format(offset))
    old = get_structure(ctx, name, category_path)
    defined_before = int(structure.getNumDefinedComponents())
    tx_id = _start_mutation_transaction(ctx, "Delete structure field")
    commit = False
    try:
        try:
            structure.deleteAtOffset(offset)
            # deleteAtOffset shifts later components into the vacated offset.
            # The next field can be defined, so verify the defined count.
            if int(structure.getNumDefinedComponents()) != defined_before - 1:
                raise ValueError("Structure defined-field count did not decrease")
            stored = get_structure(ctx, name, category_path)
            commit = True
            return _structure_mutation_result(
                "delete_structure_field", "success", requested, old, stored)
        except Exception as exc:
            return _structure_mutation_result(
                "delete_structure_field", "rolled_back", requested, old,
                error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def set_structure_layout(ctx: ProgramContext, name: str, category_path: str,
                         packing: str, alignment: str,
                         packing_value: int = 0,
                         alignment_value: int = 0) -> Dict[str, Any]:
    """Set packing and minimum-alignment policy with read-back."""
    requested = {
        "name": name, "category_path": category_path, "packing": packing,
        "packing_value": packing_value, "alignment": alignment,
        "alignment_value": alignment_value,
    }
    if packing not in ("disabled", "default", "explicit"):
        return _structure_mutation_result(
            "set_structure_layout", "validation_failed", requested, {},
            error="packing must be disabled, default, or explicit")
    if alignment not in ("default", "machine", "explicit"):
        return _structure_mutation_result(
            "set_structure_layout", "validation_failed", requested, {},
            error="alignment must be default, machine, or explicit")
    if packing == "explicit" and packing_value <= 0:
        return _structure_mutation_result(
            "set_structure_layout", "validation_failed", requested, {},
            error="packing_value must be positive for explicit packing")
    if alignment == "explicit" and alignment_value <= 0:
        return _structure_mutation_result(
            "set_structure_layout", "validation_failed", requested, {},
            error="alignment_value must be positive for explicit alignment")
    try:
        structure = _find_structure(ctx, name, category_path)
    except ValueError as exc:
        return _structure_mutation_result(
            "set_structure_layout", "validation_failed", requested, {},
            error=str(exc))
    if structure is None:
        return _structure_mutation_result(
            "set_structure_layout", "validation_failed", requested, {},
            error="Structure '{}' not found in {}".format(name, category_path))
    old = get_structure(ctx, name, category_path)
    tx_id = _start_mutation_transaction(ctx, "Set structure layout")
    commit = False
    try:
        try:
            if packing == "disabled":
                structure.setPackingEnabled(False)
            elif packing == "default":
                structure.setToDefaultPacking()
            else:
                structure.setExplicitPackingValue(packing_value)
            if alignment == "default":
                structure.setToDefaultAligned()
            elif alignment == "machine":
                structure.setToMachineAligned()
            else:
                structure.setExplicitMinimumAlignment(alignment_value)
            stored = get_structure(ctx, name, category_path)
            if (stored["packing"] != packing
                    or stored["alignment_mode"] != alignment
                    or (packing == "explicit"
                        and stored["packing_value"] != packing_value)
                    or (alignment == "explicit"
                        and stored["minimum_alignment"] != alignment_value)):
                raise ValueError("Structure layout read-back mismatch")
            commit = True
            return _structure_mutation_result(
                "set_structure_layout", "success", requested, old, stored)
        except Exception as exc:
            return _structure_mutation_result(
                "set_structure_layout", "rolled_back", requested, old,
                error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def create_union(ctx: ProgramContext, name: str,
                 category_path: str = "/") -> Dict[str, Any]:
    """Create an empty union at an exact category path."""
    from ghidra.program.model.data import (  # type: ignore
        CategoryPath, DataTypeConflictHandler, UnionDataType,
    )

    requested = {"name": name, "category_path": category_path}
    try:
        path = CategoryPath(category_path)
    except Exception as exc:
        return _structure_mutation_result(
            "create_union", "validation_failed", requested, {},
            error="Invalid category path: " + str(exc),
        )
    if ctx.program.getDataTypeManager().getDataType(path, name) is not None:
        return _structure_mutation_result(
            "create_union", "validation_failed", requested, {},
            error="Data type already exists at {}/{}".format(
                category_path, name
            ),
        )
    old = {"exists": False}
    tx_id = _start_mutation_transaction(ctx, "Create union")
    commit = False
    try:
        try:
            created = UnionDataType(
                path, name, ctx.program.getDataTypeManager()
            )
            ctx.program.getDataTypeManager().addDataType(
                created, DataTypeConflictHandler.DEFAULT_HANDLER
            )
            stored = get_composite(ctx, name, category_path)
            if stored.get("kind") != "union":
                raise ValueError("Union read-back mismatch")
            stored["exists"] = True
            commit = True
            return _structure_mutation_result(
                "create_union", "success", requested, old, stored
            )
        except Exception as exc:
            return _structure_mutation_result(
                "create_union", "rolled_back", requested, old,
                error=str(exc),
            )
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def set_union_field(ctx: ProgramContext, name: str, category_path: str,
                    ordinal: int, field_name: str, type_name: str,
                    mode: str = "replace", length: int = 0,
                    comment: str = "") -> Dict[str, Any]:
    """Insert or replace one union field by exact ordinal."""
    from ghidra.program.model.data import Union  # type: ignore

    requested = {
        "name": name, "category_path": category_path, "ordinal": ordinal,
        "field_name": field_name, "type_name": type_name, "mode": mode,
        "length": length, "comment": comment,
    }
    composite = _find_composite(ctx, name, category_path)
    if not isinstance(composite, Union):
        return _structure_mutation_result(
            "set_union_field", "validation_failed", requested, {},
            error="Union '{}' not found in {}".format(name, category_path),
        )
    if mode not in ("insert", "replace"):
        return _structure_mutation_result(
            "set_union_field", "validation_failed", requested, {},
            error="mode must be insert or replace",
        )
    count = composite.getNumComponents()
    if ordinal < 0 or ordinal > count or (mode == "replace" and ordinal == count):
        return _structure_mutation_result(
            "set_union_field", "validation_failed", requested, {},
            error="ordinal is outside the union component range",
        )
    data_type = _resolve_type(ctx.program, type_name)
    if data_type is None:
        return _structure_mutation_result(
            "set_union_field", "validation_failed", requested, {},
            error="Unknown type: " + type_name,
        )
    effective_length = length if length > 0 else data_type.getLength()
    if effective_length <= 0:
        return _structure_mutation_result(
            "set_union_field", "validation_failed", requested, {},
            error="A positive length is required for dynamic type " + type_name,
        )
    requested["effective_length"] = effective_length
    old = get_composite(ctx, name, category_path)
    tx_id = _start_mutation_transaction(ctx, "Edit union field")
    commit = False
    try:
        try:
            if mode == "replace":
                composite.delete(ordinal)
            component = composite.insert(
                ordinal, data_type, effective_length, field_name, comment
            )
            if (component.getOrdinal() != ordinal
                    or component.getFieldName() != field_name
                    or component.getLength() != effective_length
                    or not data_type.isEquivalent(component.getDataType())):
                raise ValueError("Union field read-back mismatch")
            stored = get_composite(ctx, name, category_path)
            commit = True
            return _structure_mutation_result(
                "set_union_field", "success", requested, old, stored
            )
        except Exception as exc:
            return _structure_mutation_result(
                "set_union_field", "rolled_back", requested, old,
                error=str(exc),
            )
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def set_composite_bitfield(
        ctx: ProgramContext, name: str, category_path: str, ordinal: int,
        field_name: str, type_name: str, bit_size: int,
        mode: str = "insert", byte_offset: int = 0,
        storage_size: int = 0,
        bit_offset: int = 0) -> Dict[str, Any]:
    """Insert or replace an exact structure or union bitfield."""
    from ghidra.program.model.data import (  # type: ignore
        BitFieldDataType, Structure, Union,
    )

    requested = {
        "name": name, "category_path": category_path, "ordinal": ordinal,
        "field_name": field_name, "type_name": type_name,
        "bit_size": bit_size, "mode": mode, "byte_offset": byte_offset,
        "storage_size": storage_size, "bit_offset": bit_offset,
    }
    comment = ""
    composite = _find_composite(ctx, name, category_path)
    if composite is None:
        return _structure_mutation_result(
            "set_composite_bitfield", "validation_failed", requested, {},
            error="Composite '{}' not found in {}".format(name, category_path),
        )
    if mode not in ("insert", "replace") or bit_size < 0:
        return _structure_mutation_result(
            "set_composite_bitfield", "validation_failed", requested, {},
            error="mode must be insert or replace and bit_size non-negative",
        )
    base_type = _resolve_type(ctx.program, type_name)
    if (base_type is None
            or not BitFieldDataType.isValidBaseDataType(base_type)):
        return _structure_mutation_result(
            "set_composite_bitfield", "validation_failed", requested, {},
            error="Invalid bitfield base type: " + type_name,
        )
    count = composite.getNumComponents()
    if ordinal < 0 or ordinal > count or (mode == "replace" and ordinal == count):
        return _structure_mutation_result(
            "set_composite_bitfield", "validation_failed", requested, {},
            error="ordinal is outside the composite component range",
        )
    if (isinstance(composite, Structure)
            and (byte_offset < 0 or storage_size <= 0 or bit_offset < 0)):
        return _structure_mutation_result(
            "set_composite_bitfield", "validation_failed", requested, {},
            error="Structure bitfields require non-negative byte/bit offsets "
                  "and a positive storage_size",
        )
    if mode == "replace" and not composite.getComponent(
            ordinal).isBitFieldComponent():
        return _structure_mutation_result(
            "set_composite_bitfield", "validation_failed", requested, {},
            error="replace requires an existing bitfield at ordinal {}".format(
                ordinal
            ),
        )
    old = get_composite(ctx, name, category_path)
    tx_id = _start_mutation_transaction(ctx, "Edit composite bitfield")
    commit = False
    try:
        try:
            if mode == "replace":
                if isinstance(composite, Structure):
                    composite.clearComponent(ordinal)
                else:
                    composite.delete(ordinal)
            if isinstance(composite, Union):
                component = composite.insertBitField(
                    ordinal, base_type, bit_size, field_name, comment
                )
            else:
                component = composite.insertBitFieldAt(
                    byte_offset, storage_size, bit_offset, base_type,
                    bit_size, field_name, comment,
                )
            stored_type = component.getDataType()
            if (not component.isBitFieldComponent()
                    or component.getFieldName() != field_name
                    or not isinstance(stored_type, BitFieldDataType)
                    or not base_type.isEquivalent(stored_type.getBaseDataType())
                    or stored_type.getDeclaredBitSize() != bit_size
                    or (isinstance(composite, Structure)
                        and (component.getOffset() != byte_offset
                             or stored_type.getBitOffset() != bit_offset))):
                raise ValueError("Composite bitfield read-back mismatch")
            stored = get_composite(ctx, name, category_path)
            commit = True
            return _structure_mutation_result(
                "set_composite_bitfield", "success", requested, old, stored
            )
        except Exception as exc:
            return _structure_mutation_result(
                "set_composite_bitfield", "rolled_back", requested, old,
                error=str(exc),
            )
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def delete_composite_field(ctx: ProgramContext, name: str,
                           category_path: str,
                           ordinal: int) -> Dict[str, Any]:
    """Delete a structure or union field by exact ordinal."""
    from ghidra.program.model.data import Structure  # type: ignore

    requested = {
        "name": name, "category_path": category_path, "ordinal": ordinal,
    }
    composite = _find_composite(ctx, name, category_path)
    if (composite is None or ordinal < 0
            or ordinal >= composite.getNumComponents()):
        return _structure_mutation_result(
            "delete_composite_field", "validation_failed", requested, {},
            error="Composite or ordinal not found",
        )
    if composite.getComponent(ordinal).isUndefined():
        return _structure_mutation_result(
            "delete_composite_field", "validation_failed", requested, {},
            error="No defined field exists at ordinal {}".format(ordinal),
        )
    old = get_composite(ctx, name, category_path)
    old_defined_count = composite.getNumDefinedComponents()
    tx_id = _start_mutation_transaction(ctx, "Delete composite field")
    commit = False
    try:
        try:
            if isinstance(composite, Structure):
                composite.clearComponent(ordinal)
            else:
                composite.delete(ordinal)
            if composite.getNumDefinedComponents() != old_defined_count - 1:
                raise ValueError("Composite field deletion read-back mismatch")
            stored = get_composite(ctx, name, category_path)
            commit = True
            return _structure_mutation_result(
                "delete_composite_field", "success", requested, old, stored
            )
        except Exception as exc:
            return _structure_mutation_result(
                "delete_composite_field", "rolled_back", requested, old,
                error=str(exc),
            )
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def set_composite_layout(
        ctx: ProgramContext, name: str, category_path: str,
        packing: str, alignment: str, packing_value: int = 0,
        alignment_value: int = 0) -> Dict[str, Any]:
    """Set structure or union packing/alignment with exact read-back."""
    requested = {
        "name": name, "category_path": category_path, "packing": packing,
        "packing_value": packing_value, "alignment": alignment,
        "alignment_value": alignment_value,
    }
    if (packing not in ("disabled", "default", "explicit")
            or alignment not in ("default", "machine", "explicit")):
        return _structure_mutation_result(
            "set_composite_layout", "validation_failed", requested, {},
            error="Invalid packing or alignment mode",
        )
    if ((packing == "explicit" and packing_value <= 0)
            or (alignment == "explicit" and alignment_value <= 0)):
        return _structure_mutation_result(
            "set_composite_layout", "validation_failed", requested, {},
            error="Explicit packing/alignment values must be positive",
        )
    composite = _find_composite(ctx, name, category_path)
    if composite is None:
        return _structure_mutation_result(
            "set_composite_layout", "validation_failed", requested, {},
            error="Composite '{}' not found in {}".format(name, category_path),
        )
    old = get_composite(ctx, name, category_path)
    tx_id = _start_mutation_transaction(ctx, "Set composite layout")
    commit = False
    try:
        try:
            if packing == "disabled":
                composite.setPackingEnabled(False)
            elif packing == "default":
                composite.setToDefaultPacking()
            else:
                composite.setExplicitPackingValue(packing_value)
            if alignment == "default":
                composite.setToDefaultAligned()
            elif alignment == "machine":
                composite.setToMachineAligned()
            else:
                composite.setExplicitMinimumAlignment(alignment_value)
            stored = get_composite(ctx, name, category_path)
            if (stored["packing"] != packing
                    or stored["alignment_mode"] != alignment
                    or (packing == "explicit"
                        and stored["packing_value"] != packing_value)
                    or (alignment == "explicit"
                        and stored["minimum_alignment"] != alignment_value)):
                raise ValueError("Composite layout read-back mismatch")
            commit = True
            return _structure_mutation_result(
                "set_composite_layout", "success", requested, old, stored
            )
        except Exception as exc:
            return _structure_mutation_result(
                "set_composite_layout", "rolled_back", requested, old,
                error=str(exc),
            )
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


__all__ = [
    "list_structures",
    "_find_structure",
    "get_structure",
    "_find_composite",
    "get_composite",
    "create_structure",
    "_find_first_structure",
    "_structure_state_by_name",
    "set_structure_name",
    "delete_structure",
    "_structure_mutation_result",
    "set_structure_field",
    "delete_structure_field",
    "set_structure_layout",
    "create_union",
    "set_union_field",
    "set_composite_bitfield",
    "delete_composite_field",
    "set_composite_layout",
]
