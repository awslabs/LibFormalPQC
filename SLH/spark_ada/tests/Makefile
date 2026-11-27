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

#  NIST ACVP test vectors, from ../../acvp/*.json (shared by all
#  implementations of SLH-DSA in this repository)
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

acvp_input.txt: check_acvp.py ../../acvp/*.json
	$(PYTHON) check_acvp.py input $@

acvp_results.txt: tkats acvp_input.txt
	@echo "--- Running tkats acvp ---"
	./tkats acvp <acvp_input.txt >$@

#  gprbuild is always run, since make can't tell when CONTRACTS has
#  changed. gprbuild only rebuilds what is out of date, but the tests
#  are always re-run.
tkats: FORCE
	@echo "--- Building tkats ---"
	gprbuild -s -Ptkats $(GPR_FLAGS)

FORCE:

#---------------------------------------------------------------------
#  Benchmarks
#
#  "make bench" builds tbench (tbench.adb) for every build variant of
#  the library, runs each one, and prints a summary of the median CPU
#  cycles for SLH_Keygen, SLH_Sign and SLH_Verify. The variants are
#  every combination of BENCH_MODES, BENCH_RUNTIME_CHECKS and
#  BENCH_CONTRACTS below (the SLH_BUILD_MODE, SLH_RUNTIME_CHECKS and
#  SLH_CONTRACTS variables of ../slh.gpr). The "profile" build mode is
#  left out, since it is O2 with debug information.
#
#  BENCH_CONTRACTS is "disabled" by default. With contract checks, the
#  postconditions recompute whole trees: at O2, one SLH_Keygen took
#  about 90 s (against 0.06 s without), and one SLH_Sign more than 7
#  minutes. To include them anyway, use for example
#  make bench BENCH_CONTRACTS="enabled disabled" BENCH_ITER="1 1 1"
#
#  LibKeccak is always built optimized and without runtime checks, so
#  only the SLH code differs between the variants.
#
#  The cycle counter is the one from mlkem-native, in ../../hal. On
#  macOS it needs root, so each benchmark is run with $(BENCH_RUN),
#  which is "sudo" there. sudo may ask for a password.
#
#  BENCH_ITER is the number of timed runs of keygen, sign and verify.
#---------------------------------------------------------------------
BENCH_MODES          ?= debug Og O1 O2 O3 Os
BENCH_RUNTIME_CHECKS ?= enabled disabled
BENCH_CONTRACTS      ?= disabled
BENCH_ITER           ?= 10 10 50

ifeq ($(HOSTOS),Darwin)
BENCH_RUN ?= sudo
else
BENCH_RUN ?=
endif

KECCAK_FLAGS := -XLIBKECCAK_BUILD_MODE=optimize -XLIBKECCAK_RUNTIME_CHECKS=disabled

BENCH_VARIANTS := $(foreach m,$(BENCH_MODES),$(foreach r,$(BENCH_RUNTIME_CHECKS),\
                    $(foreach c,$(BENCH_CONTRACTS),$(m)-rtc_$(r)-contracts_$(c))))

#  The variants share the library's object directory, so they are built
#  one at a time, each into its own executable bench/tbench-VARIANT
bench_build:
	@for v in $(BENCH_VARIANTS); do \
	  m=$${v%%-*}; rest=$${v#*-rtc_}; r=$${rest%%-*}; c=$${v##*-contracts_}; \
	  echo "--- Building tbench-$$v ---"; \
	  gprbuild -s -q -Ptbench -XSLH_HOSTOS=$(HOSTOS) -XSLH_BUILD_MODE=$$m \
	    -XSLH_RUNTIME_CHECKS=$$r -XSLH_CONTRACTS=$$c -XSLH_BENCH_VARIANT=$$v \
	    $(KECCAK_FLAGS) || exit 1; \
	done

bench_run: bench_build
	@for v in $(BENCH_VARIANTS); do \
	  echo "--- Running tbench-$$v ---"; \
	  $(BENCH_RUN) ./bench/tbench-$$v $$v $(BENCH_ITER) >bench/$$v.txt || exit 1; \
	done

bench: bench_run bench_report.py
	@echo "--- Benchmark summary ---"
	@$(PYTHON) bench_report.py $(addprefix bench/,$(addsuffix .txt,$(BENCH_VARIANTS))) \
	  | tee bench/summary.txt

clean:
	gprclean -r -Ptkats $(GPR_FLAGS)
	rm -rf bench
	rm -f hash_kats_results.txt wots_kats_results.txt xmss_kats_results.txt ht_kats_results.txt fors_kats_results.txt \
	      slh_kats_results.txt acvp_input.txt acvp_results.txt

.PHONY: FORCE all check check_hash check_wots check_xmss check_ht check_fors check_slh check_acvp bench bench_build bench_run clean
