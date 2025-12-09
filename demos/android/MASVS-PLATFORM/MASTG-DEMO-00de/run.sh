#!/bin/bash
#../../../../utils/frida/android/run.sh ./hooks.js

frida -U -n MASTestApp -l hooks.js -o output.json