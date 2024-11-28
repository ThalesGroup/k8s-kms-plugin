#!/usr/bin/env bash

#tpm2-abrmd --tcti swtpm:port=3333 -l stdout > /run/vtpm2/tpm2-abrmd.log 2> /run/vtpm2/tpm2-abrmd.run &
tpm2-abrmd --tcti swtpm:port="${SWTPMDATAPORT}" --allow-root -l stdout 2> "${SWTPMABRMDRUNFILE}" &
printf "$!" > "${SWTPMABRMDPIDFILE}"
