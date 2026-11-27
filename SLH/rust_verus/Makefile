#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

#  Build, verify, test and benchmark the slh_dsa crate.
#
#    make verify   run Verus on the whole library
#    make build    build the library
#    make check    build and run all the tests (the default)
#    make bench    build, run and summarize the benchmarks
#    make clean    remove everything built

HOSTOS  := $(shell uname -s)
PYTHON  ?= python3
CARGO   ?= cargo

#  The Python checkers and the NIST ACVP vectors, shared by all
#  implementations of SLH-DSA in this repository
CHECKERS := ../checkers
ACVP     := ../acvp

TKATS   := target/release/examples/tkats
RESULTS := results

all: check

verify:
	@echo "--- Verifying the library with Verus ---"
	$(CARGO) verus verify

build:
	$(CARGO) build --release

#---------------------------------------------------------------------
#  Tests
#---------------------------------------------------------------------

check: check_hash check_wots check_xmss check_ht check_fors check_slh check_acvp

#  cargo is always run, since it knows when tkats is out of date
$(TKATS): FORCE
	@echo "--- Building tkats ---"
	$(CARGO) build --release --features kat --example tkats

$(RESULTS):
	mkdir -p $@

$(RESULTS)/%_kats_results.txt: $(TKATS) | $(RESULTS)
	@echo "--- Running tkats $* ---"
	./$(TKATS) $* >$@

check_%: $(RESULTS)/%_kats_results.txt $(CHECKERS)/check_%_kats.py
	@echo "--- Checking $* KATs against the Python reference model ---"
	$(PYTHON) $(CHECKERS)/check_$*_kats.py $<

$(RESULTS)/acvp_input.txt: $(CHECKERS)/check_acvp.py $(ACVP)/*.json | $(RESULTS)
	$(PYTHON) $(CHECKERS)/check_acvp.py input $@

$(RESULTS)/acvp_results.txt: $(TKATS) $(RESULTS)/acvp_input.txt
	@echo "--- Running tkats acvp ---"
	./$(TKATS) acvp <$(RESULTS)/acvp_input.txt >$@

check_acvp: $(RESULTS)/acvp_results.txt $(CHECKERS)/check_acvp.py
	@echo "--- Checking NIST ACVP tests ---"
	$(PYTHON) $(CHECKERS)/check_acvp.py check $<

#---------------------------------------------------------------------
#  Benchmarks
#
#  "make bench" builds the benchmark program (examples/bench.rs) for
#  every build variant of the crate, runs each one, and prints a
#  summary of the median CPU cycles for slh_keygen, slh_sign and
#  slh_verify. The variants are every combination of BENCH_OPT_LEVELS
#  (the opt-level of the release profile) and BENCH_OVERFLOW_CHECKS
#  (its overflow-checks). The sha3 crate is always built at opt-level 3
#  without overflow checks (see Cargo.toml), so only this crate differs
#  between the variants.
#
#  The cycle counter is the one from mlkem-native, in ../hal. On macOS
#  it needs root, so each benchmark is run with $(BENCH_RUN), which is
#  "sudo" there. sudo may ask for a password.
#
#  BENCH_ITER is the number of timed runs of keygen, sign and verify.
#---------------------------------------------------------------------
BENCH_OPT_LEVELS      ?= 0 1 2 3 s z
BENCH_OVERFLOW_CHECKS ?= true false
BENCH_ITER            ?= 10 10 50

ifeq ($(HOSTOS),Darwin)
BENCH_RUN ?= sudo
else
BENCH_RUN ?=
endif

BENCH_DIR := bench

#  Variant names, as in the SPARK benchmark: O<level>-overflow_<checks>
ovf_name = $(if $(filter true,$(1)),enabled,disabled)
BENCH_VARIANTS := $(foreach o,$(BENCH_OPT_LEVELS),$(foreach c,$(BENCH_OVERFLOW_CHECKS),\
                    O$(o)-overflow_$(call ovf_name,$(c))))

#  Each variant is built in turn, by overriding the release profile, and
#  its executable copied to bench/bench-VARIANT
bench_build:
	@mkdir -p $(BENCH_DIR)
	@for o in $(BENCH_OPT_LEVELS); do for c in $(BENCH_OVERFLOW_CHECKS); do \
	  if [ $$c = true ]; then v=O$$o-overflow_enabled; else v=O$$o-overflow_disabled; fi; \
	  echo "--- Building bench-$$v ---"; \
	  CARGO_PROFILE_RELEASE_OPT_LEVEL=$$o CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=$$c \
	    $(CARGO) build -q --release --features bench --example bench || exit 1; \
	  cp target/release/examples/bench $(BENCH_DIR)/bench-$$v || exit 1; \
	done; done

bench_run: bench_build
	@for v in $(BENCH_VARIANTS); do \
	  echo "--- Running bench-$$v ---"; \
	  $(BENCH_RUN) ./$(BENCH_DIR)/bench-$$v $$v $(BENCH_ITER) >$(BENCH_DIR)/$$v.txt || exit 1; \
	done

bench: bench_run $(CHECKERS)/bench_report.py
	@echo "--- Benchmark summary ---"
	@$(PYTHON) $(CHECKERS)/bench_report.py $(addprefix $(BENCH_DIR)/,$(addsuffix .txt,$(BENCH_VARIANTS))) \
	  | tee $(BENCH_DIR)/summary.txt

clean:
	$(CARGO) clean
	rm -rf $(RESULTS) $(BENCH_DIR)

FORCE:

.PHONY: FORCE all verify build check check_acvp bench bench_build bench_run clean
