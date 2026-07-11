from __future__ import annotations

from typing import Any

from .merkle import merkle_root


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def verify_packed_tree_header(tree: Any, entries: Any, *, label: str = "chain") -> list[str]:
    errors: list[str] = []
    if not isinstance(tree, dict):
        return [f"{label} tree must be an object"]

    size = tree.get("size")
    root = tree.get("root")
    size_ok = type(size) is int and size >= 0
    root_ok = _is_sha256_hex(root)
    if not size_ok:
        errors.append(f"{label} tree size must be a non-negative integer")
    if not root_ok:
        errors.append(f"{label} tree root must be a SHA-256 hex digest")

    packed_entries = entries if isinstance(entries, list) else []
    valid_entries = [entry for entry in packed_entries if isinstance(entry, dict)]
    if not size_ok:
        return errors

    if len(valid_entries) > size:
        errors.append(f"{label} tree size is smaller than packed entry count")

    indexes: list[int] = []
    ids_by_index: dict[int, str] = {}
    for entry in valid_entries:
        index = entry.get("index")
        if type(index) is not int:
            continue
        indexes.append(index)
        entry_id = entry.get("entry_id")
        if isinstance(entry_id, str):
            ids_by_index[index] = entry_id

    if indexes:
        if len(set(indexes)) != len(indexes):
            errors.append(f"{label} entries contain duplicate indexes")
        if max(indexes) >= size:
            errors.append(f"{label} tree size is smaller than packed entry indexes")

    complete_indexes = list(range(size))
    if root_ok and sorted(indexes) == complete_indexes and len(ids_by_index) == size:
        entry_ids = [ids_by_index[index] for index in complete_indexes]
        if root != merkle_root(entry_ids):
            errors.append(f"{label} tree root does not match packed entries")

    return errors
