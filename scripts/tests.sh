#!/usr/bin/env sh

set -eu

main() {
    cd tests

    for pfile in ./test_*.py; do
        echo " * running $pfile"
        python3 "$pfile"
    done
}

main "$@"

