#!/bin/bash
# clean_b153_singlequote: single-quoted -c body — shell does not expand $VAR here — clean.
python3 -c 'print("$VAR")'
