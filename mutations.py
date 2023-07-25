import random
from typing import Callable


def byte_replace(b: bytes) -> bytes:
    if len(b) == 0:
        raise ValueError("Mutation precondition didn't hold.")
    index: int = random.randint(0, len(b) - 1)
    return b[:index] + bytes([random.randint(0, 255)]) + b[index + 1 :]


def byte_insert(b: bytes) -> bytes:
    index: int = random.randint(0, len(b))
    return b[:index] + bytes([random.randint(0, 255)]) + b[index:]


def byte_delete(b: bytes) -> bytes:
    if len(b) <= 1:
        raise ValueError("Mutation precondition didn't hold.")
    index: int = random.randint(0, len(b) - 1)
    return b[:index] + b[index + 1 :]


MUTATORS: list[Callable[[bytes], bytes]] = [
    byte_delete,
    byte_insert,
    byte_replace,
]
