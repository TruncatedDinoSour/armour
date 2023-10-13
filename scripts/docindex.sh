#!/usr/bin/env sh

set -eu

main() {
    printf '%s ... ' 'generating documentation index'

    rm -f -- doc/README.md

    {
        echo "# armour documentation index"

        for file in doc/d/*.md; do
            echo "- [$(head -n 1 "$file" | sed 's/^# //')](/$file)"
        done
    } >doc/README.md

    echo 'done'
}

main "$@"
