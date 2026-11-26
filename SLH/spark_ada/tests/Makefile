#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

HOSTOS := $(shell uname -s)
PYTHON ?= python3

#  CONTRACTS=disabled (the default) builds the library without runtime
#  checks of contracts and assertions. Runtime checks (ranges, overflow,
#  indexing) are still enabled. gnatprove proves all the contracts, and
#  some postconditions recompute whole subtrees, so checking them at
#  runtime is slow: the XMSS KATs take about 6 minutes with
#  CONTRACTS=enabled, and about 1 second without.
#
#  The library (../slh.gpr) shares its object directory with any other
#  build of it, such as "gprbuild -P slh.gpr", which enables contracts
#  by default. gprbuild -s recompiles any unit whose compiler switches
#  have changed, so the tests always use a library built with the
#  switches given here.
CONTRACTS ?= disabled
GPR_FLAGS := -XSLH_HOSTOS=$(HOSTOS) -XSLH_CONTRACTS=$(CONTRACTS)

all: check

check: check_hash check_wots check_xmss check_ht check_fors check_slh check_acvp

check_hash: hash_kats_results.txt check_hash_kats.py
	@echo "--- Checking hash function KATs against Python hashlib ---"
	$(PYTHON) check_hash_kats.py hash_kats_results.txt

check_wots: wots_kats_results.txt check_wots_kats.py check_hash_kats.py
	@echo "--- Checking WOTS+ KATs against the Python reference model ---"
	$(PYTHON) check_wots_kats.py wots_kats_results.txt

check_xmss: xmss_kats_results.txt check_xmss_kats.py check_wots_kats.py check_hash_kats.py
	@echo "--- Checking XMSS KATs against the Python reference model ---"
	$(PYTHON) check_xmss_kats.py xmss_kats_results.txt

check_ht: ht_kats_results.txt check_ht_kats.py check_xmss_kats.py check_wots_kats.py check_hash_kats.py
	@echo "--- Checking hypertree KATs against the Python reference model ---"
	$(PYTHON) check_ht_kats.py ht_kats_results.txt

check_fors: fors_kats_results.txt check_fors_kats.py check_xmss_kats.py check_wots_kats.py check_hash_kats.py
	@echo "--- Checking FORS KATs against the Python reference model ---"
	$(PYTHON) check_fors_kats.py fors_kats_results.txt

check_slh: slh_kats_results.txt check_slh_kats.py check_fors_kats.py check_ht_kats.py check_xmss_kats.py check_wots_kats.py check_hash_kats.py
	@echo "--- Checking SLH-DSA KATs against the Python reference model ---"
	$(PYTHON) check_slh_kats.py slh_kats_results.txt

#  NIST ACVP test vectors, from acvp/*.json
check_acvp: acvp_results.txt check_acvp.py
	@echo "--- Checking NIST ACVP tests ---"
	$(PYTHON) check_acvp.py check acvp_results.txt

hash_kats_results.txt: tkats
	@echo "--- Running tkats hash ---"
	./tkats hash >$@

wots_kats_results.txt: tkats
	@echo "--- Running tkats wots ---"
	./tkats wots >$@

xmss_kats_results.txt: tkats
	@echo "--- Running tkats xmss ---"
	./tkats xmss >$@

ht_kats_results.txt: tkats
	@echo "--- Running tkats ht ---"
	./tkats ht >$@

fors_kats_results.txt: tkats
	@echo "--- Running tkats fors ---"
	./tkats fors >$@

slh_kats_results.txt: tkats
	@echo "--- Running tkats slh ---"
	./tkats slh >$@

acvp_input.txt: check_acvp.py acvp/*.json
	$(PYTHON) check_acvp.py input $@

acvp_results.txt: tkats acvp_input.txt
	@echo "--- Running tkats acvp ---"
	./tkats acvp <acvp_input.txt >$@

tkats: tkats.gpr tkats.adb ../src/*.ads ../src/*.adb
	@echo "--- Building tkats ---"
	gprbuild -s -Ptkats $(GPR_FLAGS)

clean:
	gprclean -r -Ptkats $(GPR_FLAGS)
	rm -f hash_kats_results.txt wots_kats_results.txt xmss_kats_results.txt ht_kats_results.txt fors_kats_results.txt \
	      slh_kats_results.txt acvp_input.txt acvp_results.txt

.PHONY: all check check_hash check_wots check_xmss check_ht check_fors check_slh check_acvp clean
