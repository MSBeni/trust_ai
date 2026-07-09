from __future__ import annotations

from hashlib import sha256

LEAF_PREFIX = b"trustai-merkle-leaf-v1\x00"
NODE_PREFIX = b"trustai-merkle-node-v1\x00"
EMPTY_ROOT = sha256(b"trustai-empty-merkle-tree-v1").hexdigest()


def leaf_hash(entry_id: str) -> str:
    return sha256(LEAF_PREFIX + entry_id.encode("utf-8")).hexdigest()


def node_hash(left_hex: str, right_hex: str) -> str:
    left = bytes.fromhex(left_hex)
    right = bytes.fromhex(right_hex)
    return sha256(NODE_PREFIX + left + right).hexdigest()


def _next_level(level: list[str]) -> list[str]:
    next_hashes: list[str] = []
    for index in range(0, len(level), 2):
        if index + 1 >= len(level):
            next_hashes.append(level[index])
        else:
            next_hashes.append(node_hash(level[index], level[index + 1]))
    return next_hashes


def merkle_root(entry_ids: list[str]) -> str:
    if not entry_ids:
        return EMPTY_ROOT
    level = [leaf_hash(entry_id) for entry_id in entry_ids]
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def inclusion_proof(entry_ids: list[str], index: int) -> list[dict[str, str]]:
    if index < 0 or index >= len(entry_ids):
        raise IndexError("entry index outside tree")
    proof: list[dict[str, str]] = []
    level = [leaf_hash(entry_id) for entry_id in entry_ids]
    cursor = index
    while len(level) > 1:
        if cursor % 2 == 0:
            sibling = cursor + 1
            if sibling < len(level):
                proof.append({"position": "right", "hash": level[sibling]})
        else:
            sibling = cursor - 1
            proof.append({"position": "left", "hash": level[sibling]})
        level = _next_level(level)
        cursor //= 2
    return proof


def verify_inclusion(entry_id: str, proof: list[dict[str, str]], expected_root: str) -> bool:
    computed = leaf_hash(entry_id)
    for step in proof:
        position = step.get("position")
        sibling_hash = step.get("hash")
        if not sibling_hash:
            return False
        if position == "left":
            computed = node_hash(sibling_hash, computed)
        elif position == "right":
            computed = node_hash(computed, sibling_hash)
        else:
            return False
    return computed == expected_root
