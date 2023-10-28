#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test gen"""

from warnings import filterwarnings as filter_warnings

import armour


def main() -> int:
    """entry / main function"""

    print(
        armour.gen.info.PasswordInfo(b"hello wooorld" + armour.crypt.RAND.randbytes(10))
    )

    print()

    print(armour.gen.gen.PwGenerator(length=5192).gen())

    assert (
        armour.gen.gen.PwGenerator(min_actual_strength=100000000).gen() is None
    ), "no ."
    assert (
        armour.gen.gen.PwGenerator(min_actual_strength=6000).gen() is not None
    ), "no 1 ."

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
