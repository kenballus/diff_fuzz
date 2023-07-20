# This relies on the internal workings of the re module, so don't be surprised if it crashes or doesn't
# work on versions of Python other than 3.11.3.
# I do not want to support Unicode, because it would be way harder. This only works for bytes.
# If you want something that supports Unicode, consider using hypothesis.strategies.from_regex.
# This also does not support \A, \Z, \b, ^, and $.

import re
from re._constants import _NamedIntConstant as RegexConstant  # type: ignore
from re._parser import (  # type: ignore
    IN,
    CATEGORY_DIGIT,
    CATEGORY_NOT_DIGIT,
    CATEGORY_WORD,
    CATEGORY_NOT_WORD,
    CATEGORY_SPACE,
    CATEGORY_NOT_SPACE,
    SubPattern,
    LITERAL,
    NOT_LITERAL,
    MAX_REPEAT,
    MAXREPEAT,
    SUBPATTERN,
    NEGATE,
    RANGE,
    CATEGORY,
    BRANCH,
    ANY,
)
import random
from typing import Iterable

WORD_CHARSET: frozenset[int] = frozenset(
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz\xaa\xb2\xb3\xb5\xb9\xba\xbc\xbd\xbe\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
SPACE_CHARSET: frozenset[int] = frozenset(b"\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0")
DIGIT_CHARSET: frozenset[int] = frozenset(b"0123456789")
ALL_CHARSET: frozenset[int] = frozenset(range(256))


def category_to_charset(category: RegexConstant) -> frozenset[int]:
    if category == CATEGORY_DIGIT:
        return DIGIT_CHARSET
    if category == CATEGORY_NOT_DIGIT:
        return negate_charset(DIGIT_CHARSET)
    if category == CATEGORY_WORD:
        return WORD_CHARSET
    if category == CATEGORY_NOT_WORD:
        return negate_charset(WORD_CHARSET)
    if category == CATEGORY_SPACE:
        return SPACE_CHARSET
    if category == CATEGORY_NOT_SPACE:
        return negate_charset(SPACE_CHARSET)
    raise NotImplementedError(f"I don't know how to generate examples of {category}")


def negate_charset(charset: Iterable[int]) -> frozenset[int]:
    return ALL_CHARSET - set(charset)


def generate_random_match_from_pattern(pattern: bytes | str) -> bytes:
    return generate_random_match_from_tree(re._parser.parse(pattern))


def generate_random_match_from_tree(parse_tree: SubPattern) -> bytes:
    """
    This takes the parse tree output from re._parser.parse and
    returns a bytes object that matches the parse tree.
    """
    result: bytes = b""
    if len(parse_tree) == 0:
        return result
    curr = parse_tree[0]  # I don't know what type to put here.
    node_type: RegexConstant = curr[0]
    node_value = curr[1]  # I don't know what type to put here.
    if node_type == LITERAL:
        code_point: int = node_value
        result = bytes([code_point])
    elif node_type == NOT_LITERAL:
        forbidden_code_point: int = node_value
        result = generate_random_match_from_tree(
            [(IN, [(LITERAL, b) for b in negate_charset([forbidden_code_point])])]
        )
    elif node_type == MAX_REPEAT:
        min_reps: int = node_value[0]
        max_reps: int | RegexConstant = node_value[1]
        if min_reps == 0 and (max_reps == MAXREPEAT or max_reps > min_reps):
            min_reps = 1
        subpattern: SubPattern = node_value[2]
        for _ in range(min_reps):
            result += generate_random_match_from_tree(subpattern)
    elif node_type == SUBPATTERN:
        result = generate_random_match_from_tree(node_value[3])
    elif node_type == IN:
        # This needs to handle literal, range, and category
        # It also needs to handle negations for all of those
        need_to_negate: bool = False
        charset: set[int] = set()
        for subpattern in node_value:
            if subpattern[0] == NEGATE:
                need_to_negate = not need_to_negate
            elif subpattern[0] == LITERAL:
                charset |= set([subpattern[1]])
            elif subpattern[0] == RANGE:
                charset |= set(range(subpattern[1][0], subpattern[1][1] + 1))
            elif subpattern[0] == CATEGORY:
                charset |= category_to_charset(subpattern[1])
            else:
                raise NotImplementedError(f"I don't know how to generate examples of {subpattern[0]}")
        result = bytes([random.choice(list(negate_charset(charset) if need_to_negate else charset))])
    elif node_type == BRANCH:
        result = generate_random_match_from_tree(random.choice(node_value[1]))
    elif node_type == ANY:
        result = generate_random_match_from_tree([(IN, [(LITERAL, b) for b in ALL_CHARSET])])
    else:
        raise NotImplementedError(f"I don't know how to generate examples of {node_type}")

    return result + generate_random_match_from_tree(parse_tree[1:])
