#!/usr/bin/env sh

set -xe

main() {
    tox

    ./scripts/docindex.sh

    git add -A
    git commit -sa
    git push -u origin "$(git rev-parse --abbrev-ref HEAD)"

    deactivate || :

    [ ! "$DO_PYPI" ] || ./scripts/pypi.sh
}

main "$@"
