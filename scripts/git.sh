#!/usr/bin/env sh

set -xe

main() {
    echo 'did u deactivate the venv'
    read -r _

    tox

    ./scripts/docindex.sh

    git add -A
    git commit -sa
    git push -u origin "$(git rev-parse --abbrev-ref HEAD)"

    [ ! "$DO_PYPI" ] || ./scripts/pypi.sh
}

main "$@"
