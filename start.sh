#!/bin/sh
export PATH="$HOME/.local/bin:$HOME/.local/node-v26.13.1-linux-x64/bin:$PATH"
cd "$(dirname "$0")" || exit 1
[ -d RextroDeobf ] && cd RextroDeobf
(xdg-open http://localhost:3000 >/dev/null 2>&1 &)
exec node server.js
