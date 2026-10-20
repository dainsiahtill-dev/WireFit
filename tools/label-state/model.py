"""Bounded immutable label-forest state, independent of the original object."""
from dataclasses import dataclass, replace


@dataclass(frozen=True, slots=True)
class LabelState:
    width: int
    height: int
    labels: tuple[int, ...]
    parents: tuple[int, ...]
    components: int
    dirty: int

    def __post_init__(self):
        if any(type(value) is not int for value in (self.width, self.height, self.components, self.dirty)):
            raise ValueError('Dimensions, component count and dirty byte must be integers, not bools')
        if not (1 <= self.width <= 16 and 1 <= self.height <= 16):
            raise ValueError('Dimensions must be in 1..16')
        if type(self.labels) is not tuple or type(self.parents) is not tuple:
            raise ValueError('Labels and parents must be tuples')
        if len(self.labels) != self.width * self.height or not 1 <= len(self.parents) <= 256:
            raise ValueError('Label shape or parent capacity is outside the bounded contract')
        if not -2147483648 <= self.components <= 2147483647 or not 0 <= self.dirty <= 255:
            raise ValueError('Components must be signed int32 and dirty an unsigned byte')
        size = len(self.parents)
        if any(type(label) is not int or not 0 <= label < size for label in self.labels):
            raise ValueError('Every pixel label must select a parent entry')
        if any(type(parent) is not int or not -2147483648 <= parent < size for parent in self.parents):
            raise ValueError('Parents must be negative int32 root markers or valid indices')
        settled = set()
        for start in range(size):
            path = set()
            current = start
            while current not in settled:
                if current in path:
                    raise ValueError('Parent graph must be an acyclic forest, including unused entries')
                path.add(current)
                following = self.parents[current]
                if following < 0:
                    break
                current = following
            settled.update(path)


@dataclass(frozen=True, slots=True)
class LookupResult:
    state: LabelState
    representative: int


def _state(state: LabelState) -> None:
    if type(state) is not LabelState:
        raise ValueError('Expected a validated LabelState')


def _index(index: int, size: int) -> None:
    if type(index) is not int or not 0 <= index < size:
        raise ValueError('Index must be an existing entry, not a bool')


def _representative(parents: tuple[int, ...], initial: int) -> int:
    current = initial
    while parents[current] >= 0:
        current = parents[current]
    return current


def lookup(state: LabelState, index: int) -> LookupResult:
    """Resolve one pixel, compressing only its original label's parent slot."""
    _state(state)
    _index(index, len(state.labels))
    initial = state.labels[index]
    if state.parents[initial] < 0:
        return LookupResult(state, initial)
    root = _representative(state.parents, initial)
    labels, parents = list(state.labels), list(state.parents)
    labels[index] = root
    parents[initial] = root
    return LookupResult(replace(state, labels=tuple(labels), parents=tuple(parents)), root)


def merge_roots(state: LabelState, keep: int, drop: int) -> LabelState:
    """Link two distinct roots; labels remain unchanged until later resolution."""
    _state(state)
    _index(keep, len(state.parents)); _index(drop, len(state.parents))
    if keep == drop or state.parents[keep] >= 0 or state.parents[drop] >= 0:
        raise ValueError('Merge requires two different roots')
    parents = list(state.parents)
    parents[drop] = keep
    count = (state.components - 1 + 0x80000000) % 0x100000000 - 0x80000000
    return replace(state, parents=tuple(parents), components=count, dirty=1)


def normalize(state: LabelState) -> LabelState:
    """For a dirty state, resolve all pixels and reset every parent to -1."""
    _state(state)
    if state.dirty == 0:
        return state
    labels = tuple(_representative(state.parents, label) for label in state.labels)
    return replace(state, labels=labels, parents=(-1,) * len(state.parents), dirty=0)
