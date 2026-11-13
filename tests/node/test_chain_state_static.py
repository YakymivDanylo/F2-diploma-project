"""Slice 16a static checks: `ChainState` is the only chain mutator and owns the only chain lock.

AST-based over `src/node/**/*.py` (UC-17-EC2).
"""

from __future__ import annotations

import ast
from pathlib import Path

NODE_DIR = Path(__file__).resolve().parents[2] / "src" / "node"
OWNER = "chain_state.py"

MUTATORS = {"append", "insert", "extend", "pop", "remove", "clear"}
CHAIN_ATTRS = {"_blocks", "blocks"}
# derived-state updates that only ChainState may trigger
DERIVED_UPDATES = {"add_block", "on_append", "on_replace"}
LOCK_NAMES = {"Lock", "RLock"}


def _text(node: ast.AST) -> str:
  return ast.unparse(node).lower()


def _is_chain_state(node: ast.AST) -> bool:
  """A call routed through the owner: `self._chain_state`, `context.chain_state`, ..."""
  return _text(node).endswith("chain_state")


def _is_chainish(node: ast.AST) -> bool:
  text = _text(node)
  return "chain" in text or "blocks" in text


def _is_chain_class(func: ast.AST) -> bool:
  """`Chain(...)`, `core.Chain(...)` or a `Chain.from_x(...)` constructor call."""
  if isinstance(func, ast.Name):
    return func.id == "Chain"
  if isinstance(func, ast.Attribute):
    return func.attr == "Chain" or (isinstance(func.value, ast.Name) and func.value.id == "Chain")
  return False


def _assigned_targets(node: ast.AST) -> list[ast.expr]:
  if isinstance(node, ast.Assign):
    return list(node.targets)
  if isinstance(node, ast.AnnAssign | ast.AugAssign):
    return [node.target]
  return []


def find_chain_mutations(source: str) -> list[str]:
  """Descriptions (with line numbers) of every chain-mutating construct in `source`."""
  found: list[str] = []
  for node in ast.walk(ast.parse(source)):
    line = getattr(node, "lineno", 0)
    if isinstance(node, ast.Call):
      func = node.func
      if (
        isinstance(func, ast.Attribute)
        and func.attr in MUTATORS
        and _is_chainish(func.value)
        and not _is_chain_state(func.value)
      ):
        found.append(f"line {line}: {ast.unparse(func)}() mutates a chain list")
      if isinstance(func, ast.Attribute) and (
        func.attr in DERIVED_UPDATES or (func.attr == "reset" and "document" in _text(func.value))
      ):
        found.append(f"line {line}: {ast.unparse(func)}() updates derived chain state")
      if isinstance(func, ast.Attribute) and func.attr == "save" and "store" in _text(func.value):
        found.append(f"line {line}: {ast.unparse(func)}() persists the chain outside the owner")
      if _is_chain_class(func):
        found.append(f"line {line}: core Chain instance created")
    for target in _assigned_targets(node):
      for part in ast.walk(target):
        if isinstance(part, ast.Subscript) and _is_chainish(part.value):
          found.append(f"line {line}: item assignment on {ast.unparse(part.value)}")
        if isinstance(part, ast.Attribute) and part.attr in CHAIN_ATTRS:
          found.append(f"line {line}: rebinding of attribute {part.attr}")
    if isinstance(node, ast.Delete):
      for target in node.targets:
        if isinstance(target, ast.Subscript) and _is_chainish(target.value):
          found.append(f"line {line}: deletion on {ast.unparse(target.value)}")
        if isinstance(target, ast.Attribute) and target.attr in CHAIN_ATTRS:
          found.append(f"line {line}: deletion of attribute {target.attr}")
  return found


def _node_sources() -> list[tuple[Path, str]]:
  return [(p, p.read_text(encoding="utf-8")) for p in sorted(NODE_DIR.rglob("*.py"))]


def find_locks(source: str) -> list[tuple[str, int]]:
  """`(assigned name or "", line)` for every Lock()/RLock() construction in `source`."""
  locks: list[tuple[str, int]] = []
  names: dict[int, str] = {}
  tree = ast.parse(source)
  for node in ast.walk(tree):
    for target in _assigned_targets(node):
      value = getattr(node, "value", None)
      if value is not None:
        names[id(value)] = ast.unparse(target)
  for node in ast.walk(tree):
    if isinstance(node, ast.Call):
      func = node.func
      name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
      if name in LOCK_NAMES:
        locks.append((names.get(id(node), ""), node.lineno))
  return locks


def chain_locks(path: Path, source: str) -> list[str]:
  """Locks that guard the chain: named `*chain*`, or anything constructed in chain_state.py."""
  return [
    f"{path.name}:{line} ({name or 'unnamed'})"
    for name, line in find_locks(source)
    if "chain" in name.lower() or path.name == OWNER
  ]


def imports_core_chain(source: str) -> bool:
  for node in ast.walk(ast.parse(source)):
    if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "blockchain_core":
      if any(alias.name == "Chain" for alias in node.names):
        return True
    if isinstance(node, ast.Attribute) and node.attr == "Chain":
      if ast.unparse(node.value).startswith("blockchain_core"):
        return True
  return False


# --------------------------------------------------------------------- CN-TC-17.11

POSITIVE_CONTROL = """
from blockchain_core import Chain


class Rogue:
  def __init__(self, chain, blocks):
    self._chain = chain
    self.chain = Chain.from_blocks(blocks)
    self._chain.append(blocks[0])  # append
    self._chain.insert(0, blocks[0])  # insert
    chain.blocks.extend(blocks)  # extend
    self._chain.pop()  # pop
    self._chain.remove(blocks[0])  # remove
    chain.blocks.clear()  # clear
    chain[0] = blocks[1]  # item assignment
    self._blocks[1:] = blocks  # slice assignment
    del self._blocks[0]  # deletion
    self._blocks = tuple(blocks)  # rebinding
    chain.blocks += blocks  # augmented rebinding
    self.live = Chain()  # core Chain instance
    self._store.save(blocks)  # persistence outside the owner
    self.context.store.save(blocks)  # persistence outside the owner
    self.documents.add_block(blocks[0], 1)  # derived index update
    self.documents.reset(blocks)  # derived index rebuild
    self.validity_cache.on_append(blocks[0])  # derived cache update
    self.validity_cache.on_replace(blocks, None)  # derived cache update
"""

NEGATIVE_CONTROL = """
class Innocent:
  def __init__(self):
    self.needs_sync = []
    self.stale = []
    self.records = {}

  def run(self, mempool, item):
    self.needs_sync.append(item)
    stale = []
    stale.append(item)
    mempool.add(item)
    mempool.remove([item])
    self.records[item] = 1
    self.profile.save(item)  # a save on something that is not the chain store
    self.validity_cache.initialize(item)  # boot-time initialisation is allowed
    self.context.chain_state.append(item)  # routed through the owner
    self._chain_state.replace(item, None)
    DocumentIndex(item)
    blocks = list(self.needs_sync)  # a local variable named blocks is fine
    return blocks
"""


def test_positive_control_is_flagged(tmp_path: Path) -> None:
  # CN-TC-17.11
  module = tmp_path / "rogue.py"
  module.write_text(POSITIVE_CONTROL, encoding="utf-8")
  hits = find_chain_mutations(module.read_text(encoding="utf-8"))
  lines = {int(h.split(":")[0].removeprefix("line ")) for h in hits}
  source_lines = POSITIVE_CONTROL.splitlines()
  expected = {i for i, text in enumerate(source_lines, start=1) if "#" in text}
  # one flagged line for every forbidden construct in the control module
  assert expected <= lines, f"missed: {sorted(expected - lines)}; got: {hits}"
  assert any("Chain" in h for h in hits)


def test_ordinary_lists_are_not_flagged() -> None:
  # CN-TC-17.11
  assert find_chain_mutations(NEGATIVE_CONTROL) == []


def test_no_chain_mutation_outside_chain_state() -> None:
  # CN-TC-17.11
  offenders = {
    str(path.relative_to(NODE_DIR)): hits
    for path, source in _node_sources()
    if path.name != OWNER and (hits := find_chain_mutations(source))
  }
  assert offenders == {}


# --------------------------------------------------------------------- CN-TC-17.12


def test_lock_finder_detects_a_second_chain_lock() -> None:
  # CN-TC-17.12 (positive control)
  source = (
    "import asyncio\nclass X:\n  def __init__(self):\n    self._chain_lock = asyncio.Lock()\n"
  )
  assert chain_locks(Path("rogue.py"), source) == ["rogue.py:4 (self._chain_lock)"]
  unrelated = "import asyncio\nsubmission_lock = asyncio.Lock()\nx = dict(lock=asyncio.Lock())\n"
  assert chain_locks(Path("other.py"), unrelated) == []


def test_exactly_one_chain_lock_and_it_is_in_chain_state() -> None:
  # CN-TC-17.12
  locks = [lock for path, source in _node_sources() for lock in chain_locks(path, source)]
  assert len(locks) == 1, locks
  assert locks[0].startswith(OWNER)


def test_only_chain_state_may_touch_core_chain() -> None:
  # CN-TC-17.12
  assert imports_core_chain("from blockchain_core import Block, Chain\n")
  assert imports_core_chain("import blockchain_core\nx = blockchain_core.Chain\n")
  assert not imports_core_chain("from blockchain_core import Block\n")
  importers = [
    str(path.relative_to(NODE_DIR))
    for path, source in _node_sources()
    if path.name != OWNER and imports_core_chain(source)
  ]
  assert importers == []
