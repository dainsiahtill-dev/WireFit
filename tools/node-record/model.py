"""The bounded 40-byte record writer contract, independent of the original object."""
import struct


def patch_node_record(storage: bytes, node_id: int, x: int, y: int,
                      width: int, height: int) -> bytes:
    """Return a copy with the five observed fields of one record replaced.

    Unknown fields and adjacent records are preserved. Coordinates are limited
    to the recovered small-grid contract; object allocation is outside it.
    """
    if type(storage) is not bytes or len(storage) % 40 or not 40 <= len(storage) <= 40 * 289:
        raise ValueError('storage must contain 1..289 complete 40-byte records')
    if any(type(value) is not int for value in (node_id, x, y, width, height)):
        raise ValueError('node_id, coordinates and dimensions must be integers, not bools')
    if not (2 <= width <= 16 and 2 <= height <= 16):
        raise ValueError('width and height must be in 2..16')
    if not (0 <= x <= width and 0 <= y <= height):
        raise ValueError('coordinates must be within the inclusive grid boundary')
    if not 0 <= node_id < len(storage) // 40:
        raise ValueError('node_id must select an existing record')
    result = bytearray(storage)
    offset = node_id * 40
    struct.pack_into('<ddff', result, offset, x, y, x, y)
    result[offset + 28] = 3 if x in (0, width) and y in (0, height) else 0
    return bytes(result)
