"""Simplified PBFT view change: who votes for which view, and when a view is installed (UC-6-D).

A pure state machine - no asyncio, no I/O, the caller passes in already-verified votes. The
engine (`engine.py`) owns the triggers, the locks and what installing a view does to rounds.

The primary of view `v` is `members[v mod n]`. A node that gives up on its view sends a
view-change vote for a higher target view; per member only its LATEST (highest-view) vote is
kept. Rules:
- install: `v*` = the highest view such that a quorum of members have latest votes >= v*.
  Above the current view, the node moves to `v*`. A quorum includes honest nodes, so one
  Byzantine member can neither install a view nor push the view arbitrarily high;
- join: when f+1 members (so at least one honest) want a higher view, this node votes for the
  (f+1)-th highest view they want, so honest nodes that escalated separately reconverge;
- escalation: the vote for a target is re-sent unchanged until it is installed; the target is
  only raised by the join rule, or by a fresh trigger in the installed view (e.g. its new
  primary is down too) - never by a lone timer, so a node with a flaky link does not run off
  into ever higher views (UC-6-EC2: the condition is reported, never looped silently).

Explicitly NOT implemented (intentional thesis simplification, UC-6-D): PBFT state transfer,
checkpoints and watermarks. A lagging node catches up through chain sync instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from node.consensus.pbft.messages import NO_BLOCK, PbftMessage, Vote

MAX_VIEWS_AHEAD = 16  # votes for views further ahead are dropped (bounded state)


@dataclass(frozen=True)
class Outcome:
  kind: str  # "new" | "duplicate" | "stale" | "conflict"
  previous: Vote | None = None  # the conflicting vote already held, for evidence


@dataclass
class ViewChangeState:
  self_id: str
  quorum: int
  f: int
  view: int = 0
  target: int | None = None  # the view we are voting for, while not installed
  attempts: int = 0  # re-sends of our vote for `target` (reported, never silent)
  latest: dict[str, PbftMessage] = field(default_factory=dict)  # member -> latest vote
  install_votes: tuple[Vote, ...] = ()  # the signed votes that prove `install_view`
  install_view: int = -1

  @property
  def in_progress(self) -> bool:
    return self.target is not None

  def accept(self, vote: PbftMessage) -> Outcome:
    """Record a verified view-change vote (ours included)."""
    if vote.view <= self.view or vote.view > self.view + MAX_VIEWS_AHEAD:
      return Outcome("stale")
    held = self.latest.get(vote.node_id)
    if held is not None and held.view > vote.view:
      return Outcome("stale")
    if held is not None and held.view == vote.view:
      if held.seq == vote.seq and held.block_hash == vote.block_hash:
        return Outcome("duplicate")
      if (
        held.seq == vote.seq
        and NO_BLOCK not in (held.block_hash, vote.block_hash)
        and held.block_hash != vote.block_hash
      ):
        # Two different locked blocks named for one (view, seq): equivocation. A moved tip
        # (another seq) or a lock gained after a NO_BLOCK vote is an honest update.
        return Outcome("conflict", held.vote())
    self.latest[vote.node_id] = vote
    return Outcome("new")

  def accept_install_votes(self, votes: list[Vote], view: int) -> bool:
    """A new-view's verified votes: True if they show a quorum for >= `view`."""
    voters = {vote.node_id for vote in votes if vote.view >= view}
    return len(voters) >= self.quorum

  def join_target(self) -> int | None:
    """The view to vote for because f+1 OTHER members want one higher than ours, if any."""
    wanted = sorted(
      (v.view for node, v in self.latest.items() if node != self.self_id and v.view > self.view),
      reverse=True,
    )
    if len(wanted) < self.f + 1:
      return None
    target = wanted[self.f]
    return target if self.target is None or target > self.target else None

  def installable(self) -> int | None:
    """The highest view a quorum of members (us included) has voted for or beyond."""
    views = sorted((v.view for v in self.latest.values() if v.view > self.view), reverse=True)
    if len(views) < self.quorum:
      return None
    return views[self.quorum - 1]

  def start(self, target: int) -> None:
    self.target = target
    self.attempts = 0

  def cancel(self) -> None:
    self.target = None
    self.attempts = 0

  def install(self, view: int) -> tuple[PbftMessage, ...]:
    """Move to `view`; returns the votes it was installed on (kept as the install proof)."""
    supporting = tuple(v for v in self.latest.values() if v.view >= view)
    self.install_votes = tuple(v.vote() for v in supporting)
    self.install_view = view
    self.view = view
    self.latest = {node: v for node, v in self.latest.items() if v.view > view}
    own = self.latest.get(self.self_id)
    if own is None:  # our own vote is satisfied; one for a still higher view stays in force
      self.target = None
      self.attempts = 0
    return supporting

  def adopt(self, view: int) -> bool:
    """Adopt a view proven elsewhere (a finalized block or a new-view proof)."""
    if view <= self.view:
      return False
    self.view = view
    if self.target is not None and self.target <= view:
      self.target = None
      self.attempts = 0
    self.latest = {node: v for node, v in self.latest.items() if v.view > view}
    self.install_votes, self.install_view = (), -1  # a caller with a proof sets them again
    return True
