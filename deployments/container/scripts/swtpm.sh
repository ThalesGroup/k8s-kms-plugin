#!/usr/bin/env bash

# level 5 id debug
swtpm socket --server port="${SWTPMDATAPORT}" --ctrl type=tcp,port="${SWTPMCTRLPORT}" --tpm2 --tpmstate dir="${SWTPMSTATEDIR}" --flags not-need-init --pid file="${SWTPMPIDFILE}" --log file="${SWTPMLOGFILE}",level="${SWTPMLOGLEVEL}" > "${SWTPMRUNFILE}" 2>&1 &