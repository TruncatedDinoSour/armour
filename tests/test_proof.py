#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""proof script"""

import secrets
from base64 import b85encode
from subprocess import check_output
from typing import Dict
from warnings import filterwarnings as filter_warnings

import armour.gen


def main() -> int:
    """entry / main function"""

    scores: Dict[str, int] = {
        "armour": 0,
        "b85_shuf": 0,
        "b85_norm": 0,
    }

    try:
        check_output(["pwgen"])
        print("pwgen support enabled")
        scores["pwgen"] = 0
        pwgok: bool = True
    except FileNotFoundError:
        pwgok: bool = False

    runs: int = 2048
    pw_len: int = 2048

    print(f"running {runs} tests with password length {pw_len}\n")

    # re-creating every object to have a fresh test

    for idx in range(runs):
        rand: secrets.SystemRandom = secrets.SystemRandom()

        b85_norm: bytes = b85encode(rand.randbytes(pw_len * 2))[:pw_len]

        b85_shuf: list[str] = list(
            b85encode(rand.randbytes(pw_len * 2))[:pw_len].decode("ascii")
        )
        rand.shuffle(b85_shuf)

        armour_info = armour.gen.gen.PwGenerator(length=pw_len).gen()

        if armour_info is None:
            armour_pw: bytes = b""
        else:
            armour_pw = armour_info.pw

        assert (
            (a := len(b85_norm)) == (b := len(b85_shuf)) == (c := len(armour_pw))
        ), f"password lengths don't match, b85_norm {a}; b85_shuf {b}; armour {c}"

        strengths: Dict[str, float] = {
            "armour": armour.gen.info.PasswordInfo(armour_pw).actual_strength(),
            "b85_shuf": armour.gen.info.PasswordInfo(
                "".join(b85_shuf).encode("ascii")
            ).actual_strength(),
            "b85_norm": armour.gen.info.PasswordInfo(b85_norm).actual_strength(),
        }

        if pwgok:
            strengths["pwgen"] = armour.gen.info.PasswordInfo(
                check_output(["pwgen", str(pw_len), "1"]).strip()
            ).actual_strength()

        w: str = max(strengths, key=strengths.get)  # type: ignore

        print(
            f"{idx + 1:<4}",
            f"{(idx + 1) / runs * 100:<6.2f}%",
            f"{str(strengths):>128}",
            f"{w:>8}",  # type: ignore
        )

        scores[w] += 1  # type: ignore

    print()

    for k, v in scores.items():
        print(
            k,
            "with",
            v,
            "win( s ) or",
            v / runs * 100,
            "percent of the runs won",
        )

    print()

    w: str = max(scores, key=scores.get)  # type: ignore

    print(
        "winner is",
        w,  # type: ignore
        "with score",
        scores[w],  # type: ignore
        "or",
        scores[w] / runs * 100,  # type: ignore
        "percent of the runs won",
    )

    print(
        "note : you can change the default armour values to "
        "generate even better passwords"
    )

    # exits with 1 if winner is not `armour`
    return int(w != "armour")  # type: ignore


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
