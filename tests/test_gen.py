#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test gen"""

from warnings import filterwarnings as filter_warnings

import armour


def main() -> int:
    """entry / main function"""

    print(armour.gen.info.PasswordInfo(b"hello world" + armour.crypt.RAND.randbytes(10)))

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
