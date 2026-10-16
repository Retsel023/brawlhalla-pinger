#!/usr/bin/env sh

pinger_pause_on_error() {
    if [ -t 0 ]; then
        printf '\nPress Enter to close...'
        read -r pinger_answer
    fi
}

pinger_dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
cd "$pinger_dir" || exit 1

if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
    pinger_python=python3
elif command -v python >/dev/null 2>&1 && python -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
    pinger_python=python
else
    printf '%s\n' 'Python 3.9 or newer was not found.' 'Install Python 3 with your system package manager or from python.org, then run ./start.sh again.' >&2
    pinger_pause_on_error
    exit 1
fi

"$pinger_python" "$pinger_dir/pinger.py" "$@"
pinger_result=$?
if [ "$pinger_result" -ne 0 ]; then
    printf '\n%s\n' 'Brawlhalla Pinger stopped with an error. Check the message above.' 'See README.md for setup and port troubleshooting.' >&2
    pinger_pause_on_error
fi
exit "$pinger_result"
