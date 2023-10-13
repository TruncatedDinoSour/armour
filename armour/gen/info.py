#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""password info"""

from abc import ABC, abstractmethod


class PasswordInfo(ABC):
    """pase password info extractor class"""

    def __init__(self, pw: bytes) -> None:
        self.pw: bytes = pw

    @property
    def length(self) -> int:
        """returns the length of the password"""
        return len(self.pw)

    @abstractmethod
    def entropy(self) -> float:
        """password entropy"""

    @abstractmethod
    def strength(self) -> float:
        """password strength"""

    @abstractmethod
    def weakness(self) -> float:
        """password weakness"""

    @abstractmethod
    def actual_strength(self) -> float:
        """actual strength for passwords in real world"""
