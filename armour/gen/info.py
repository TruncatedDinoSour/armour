#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""password info"""

from collections import Counter
from itertools import groupby
from math import log2
from typing import Set, Tuple

__all__: Tuple[str, str] = "PasswordInfo", "patterns"

patterns: bytes = (
    b"abcdefghijklmnopqrstuvwxyz"  # alphabet
    b"qwertyuiopasdfghjklzxcvbnm"  # qwerty
    b"~!@#$%^&*()_+-="  # qwerty special
    b"01234567890"  # numbers
)
patterns += patterns[::-1]


class PasswordInfo:
    """password info extractor"""

    def __init__(self, pw: bytes) -> None:
        self.pw: bytes = pw

    @property
    def length(self) -> int:
        """returns the length of the password"""
        return len(self.pw)

    @property
    def lowercase(self) -> int:
        """lowercase letters"""
        return sum(97 <= bc <= 122 for bc in self.pw)

    @property
    def uppercase(self) -> int:
        """uppercase letters"""
        return sum(65 <= bc <= 90 for bc in self.pw)

    @property
    def numbers(self) -> int:
        """numbers"""
        return sum(48 <= bc <= 57 for bc in self.pw)

    @property
    def special(self) -> int:
        """special / other characters ( [^a-zA-Z0-9] )"""
        return sum(
            (bc < 48) or (57 < bc < 65) or (90 < bc < 97) or (bc > 122)
            for bc in self.pw
        )

    @property
    def alphabet(self) -> Set[int]:
        """alphabet"""
        return set(self.pw)

    @property
    def alphabet_len(self) -> int:
        """alphabet length"""
        return len(self.alphabet)

    @property
    def alphabet_combos(self) -> int:
        """alphabet combinations"""
        return self.alphabet_len**self.length

    @property
    def sequences(self) -> int:
        """password sequences"""
        return sum(1 for _ in groupby(self.pw))

    def common_patterns(self) -> int:
        """returns the count of common patterns"""

        sequences_length: int = 0
        idx: int = 0

        while idx < self.length:
            b_slice: bytes = self.pw[idx:]
            jdx: int = 0
            common_length: int = 1

            while (jdx := patterns.find(b_slice[0], jdx + 1)) != -1:
                common_here_len: int = 0

                for a, b_component in zip(b_slice, patterns[jdx:]):
                    if a != b_component:
                        break

                    common_here_len += 1

                common_length = max(common_length, common_here_len)

            if common_length > 2:
                sequences_length += common_length
                idx += common_length
            else:
                idx += 1

        return sequences_length

    def entropy(self) -> float:
        """password entropy by frequency analysis"""

        l: float = float(self.length)
        return -sum(
            count / l * log2((count / l)) for count in Counter(self.pw).values()
        )

    def strength(self) -> float:
        """password strength"""
        return self.entropy() * self.length

    def weakness(self) -> float:
        """password weakness"""
        return (
            self.sequences
            * (self.common_patterns() ** 2)
            * (self.lowercase if self.lowercase == self.length else 1)
            * (self.uppercase if self.uppercase == self.length else 1)
        )

    def actual_strength(self) -> float:
        """actual strength for passwords in real world"""
        return (self.strength() * self.alphabet_len) / max(1, self.weakness())
