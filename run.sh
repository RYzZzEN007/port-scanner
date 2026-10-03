#!/bin/bash
ulimit -n 4096
source venv/bin/activate
python scanner.py "$@"
