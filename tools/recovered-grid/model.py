"""Independent numbering model for the bounded 2..16 dense-label contract."""
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GridNumbering:
    nodes: tuple[int, ...]
    node_count: int


def number_grid(labels: list[int], width: int, height: int, node_stride: int) -> GridNumbering:
    """Number perimeter coordinates, then nonuniform interior junctions.

    Input labels have no row padding. Output has H+1 rows, each node_stride
    elements; padding is zero. This is a local data model, not image decoding.
    """
    if type(width) is not int or type(height) is not int or not (2 <= width <= 16 and 2 <= height <= 16):
        raise ValueError("width and height must be integers from 2 through 16")
    if type(node_stride) is not int or not width + 1 <= node_stride <= width + 8:
        raise ValueError("node_stride must be an integer from width+1 through width+8")
    if type(labels) is not list or len(labels) != width * height:
        raise ValueError("labels must be a dense width*height list")
    if any(type(label) is not int or not -(1 << 31) <= label < (1 << 31) for label in labels):
        raise ValueError("every label must be a signed int32 integer; booleans are not labels")

    border = tuple((x, y) for x in (0, width) for y in range(height + 1)) + tuple(
        (x, y) for y in (0, height) for x in range(1, width)
    )
    inside = tuple((x, y) for y in range(1, height) for x in range(1, width))
    junctions = tuple((x, y) for x, y in inside if len({
        labels[(y - 1) * width + x - 1], labels[(y - 1) * width + x],
        labels[y * width + x - 1], labels[y * width + x],
    }) > 1)
    numbered = border + junctions
    nodes = [0] * (node_stride * (height + 1))
    for x, y in inside:
        nodes[y * node_stride + x] = -1
    for node_id, (x, y) in enumerate(numbered):
        nodes[y * node_stride + x] = node_id
    return GridNumbering(tuple(nodes), len(numbered))
