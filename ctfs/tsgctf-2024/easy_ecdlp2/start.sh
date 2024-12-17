#!/bin/sh
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
export HOME=/home/sage
cd $SCRIPTPATH
./proof-of-work.py && timeout 15m sage ./problem.sage
