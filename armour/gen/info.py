#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""password info"""

from collections import Counter
from math import log, log2
from typing import Iterable, List, Set, Tuple

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

    def __init__(self, pw: bytes = b"") -> None:
        self.pw: bytes = pw

    @property
    def length(self) -> int:
        """returns the length of the password"""
        return len(self.pw)

    @property
    def lower(self) -> Tuple[int, ...]:
        """lowercase letters"""
        return tuple(bc for bc in self.pw if 97 <= bc <= 122)

    @property
    def upper(self) -> Tuple[int, ...]:
        """uppercase letters"""
        return tuple(bc for bc in self.pw if 65 <= bc <= 90)

    @property
    def numbers(self) -> Tuple[int, ...]:
        """numbers"""
        return tuple(bc for bc in self.pw if 48 <= bc <= 57)

    @property
    def special(self) -> Tuple[int, ...]:
        """special / other characters ( [^a-zA-Z0-9] )"""
        return tuple(
            bc
            for bc in self.pw
            if (bc < 48) or (57 < bc < 65) or (90 < bc < 97) or (bc > 122)
        )

    @property
    def alphabet(self) -> Set[int]:
        """alphabet"""
        return set(self.pw)

    @property
    def alphabet_combos(self) -> int:
        """alphabet combinations"""
        return len(self.alphabet) ** self.length

    def sequences(self) -> List[Tuple[int, int]]:
        """return the list of repeated sequences indexes"""

        repeats: List[Tuple[int, int]] = []
        idx: int = 0

        while idx < self.length - 1:
            if self.pw[idx] == self.pw[idx + 1]:
                start: int = idx

                while idx < self.length - 1 and self.pw[idx] == self.pw[idx + 1]:
                    idx += 1

                repeats.append((start, idx + 1))

            idx += 1

        return repeats

    def sequences_count(self) -> int:
        """return sequences count"""
        return sum(end - start for start, end in self.sequences())

    def common_patterns(self) -> List[Tuple[int, int]]:
        """returns the list of tuples which have start and
        ending indexes of the common patterns"""

        patterns_list: List[Tuple[int, int]] = []
        idx: int = 0

        while idx < self.length:
            b_slice: bytes = self.pw[idx:]
            jdx: int = 0
            common_length: int = 1

            while (jdx := patterns.find(b_slice[0], jdx + 1)) != -1:
                common_here_pattern: bytes = b""

                for a, b_component in zip(b_slice, patterns[jdx:]):
                    if a != b_component:
                        break

                    common_here_pattern += bytes((a,))

                common_length = max(common_length, len(common_here_pattern))

            if common_length > 2:
                patterns_list.append((idx, idx + common_length))
                idx += common_length
            else:
                idx += 1

        return patterns_list

    def common_patterns_count(self) -> int:
        """return common patterns count"""
        return sum(end - start for start, end in self.common_patterns())

    def entropy(self) -> float:
        """password entropy by frequency analysis"""

        l: float = float(self.length)
        return -sum(
            count / l * log2((count / l)) for count in Counter(self.pw).values()
        )

    def strength(self) -> float:
        """password strength"""
        return self.entropy() * self.length + log(self.alphabet_combos)

    def weakness(self) -> float:
        """password weakness"""

        lower_len: int = len(self.lower)
        upper_len: int = len(self.upper)
        num_len: int = len(self.numbers)

        return (
            self.sequences_count()
            * (self.common_patterns_count() ** 2)
            * (lower_len if lower_len == self.length else 1)
            * (upper_len if upper_len == self.length else 1)
            * (num_len if num_len == self.length else 1)
        )

    def actual_strength(self) -> float:
        """actual strength for passwords in real world"""
        return (self.strength() * len(self.alphabet)) / max(1, self.weakness()) / 16

    def codes_to_str(self, what: Iterable[int]) -> str:
        """convers an iterable of codes to a literal byte string"""
        return repr(bytes(what))[2:-1]

    def __str__(self) -> str:
        """return pw info as a string"""

        common_patterns: str = "\n    ".join(
            f"- {repr(self.pw[frm:to])[1:]} ( from {frm} to {to} )"
            for frm, to in self.common_patterns()
        )
        sequences: str = "\n    ".join(
            f"- {repr(self.pw[frm:to])[1:]} ( from {frm} to {to} )"
            for frm, to in self.sequences()
        )

        return f"""
length                  {self.length}
lowercase               {self.codes_to_str(self.lower) or '<none>'!r}
uppercase               {self.codes_to_str(self.upper) or '<none>'!r}
numbers                 {self.codes_to_str(self.numbers) or '<none>'!r}
special                 {self.codes_to_str(self.special) or '<none>'!r}
alphabet                {self.codes_to_str(self.alphabet) or '<none>'!r}
    alphabet combos hex {hex(self.alphabet_combos)}
sequences               {self.sequences_count()}
    {sequences or '<none>'}
common patterns         {self.common_patterns_count()}
    {common_patterns or '<none>'}
entropy bits            {self.entropy()}
strength                {self.strength()}
weakness                {self.weakness()}
actual strength         {self.actual_strength()}
""".strip()
