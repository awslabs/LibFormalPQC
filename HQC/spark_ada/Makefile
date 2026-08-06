all: binaries results diffs

binaries: hqc-1-binaries hqc-3-binaries hqc-5-binaries
results: kats/hqc-1/tinew.txt kats/hqc-1/katsnew.txt kats/hqc-3/tinew.txt kats/hqc-3/katsnew.txt kats/hqc-5/tinew.txt kats/hqc-5/katsnew.txt
diffs: ti1diff ti3diff ti5diff kats1diff kats3diff kats5diff

hqc-1-binaries: obj1/test_intermediates obj1/test_kat
hqc-3-binaries: obj3/test_intermediates obj3/test_kat
hqc-5-binaries: obj5/test_intermediates obj5/test_kat

# TARGETs for GNATProve proof runs
proofall: proof1 proof3 proof5

proof1: src/*.ads src/*.adb hqc.gpr
	gnatprove -Phqc -XHQC_PARAM=1 --report=statistics -u src/hqc.adb

proof3: src/*.ads src/*.adb hqc.gpr
	gnatprove -Phqc -XHQC_PARAM=3 --report=statistics -u src/hqc.adb

proof5: src/*.ads src/*.adb hqc.gpr
	gnatprove -Phqc -XHQC_PARAM=5 --report=statistics -u src/hqc.adb


# Switches for debug release
COMPSWITCHES=-XHQC_BUILD_MODE=debug -XHQC_RUNTIME_CHECKS=enabled -XHQC_CONTRACTS_CHECKS=enabled

# Switches for optimized release
#COMPSWITCHES=-XHQC_BUILD_MODE=O3 -XHQC_RUNTIME_CHECKS=disabled -XHQC_CONTRACTS_CHECKS=disabled

# Switches for coverage analysis
#COMPSWITCHES=-XHQC_BUILD_MODE=debug -XHQC_RUNTIME_CHECKS=disabled -XHQC_CONTRACTS_CHECKS=disabled -XHQC_COVERAGE=enabled

# Intermediate values KAT for HQC-1
ti1diff: kats/hqc-1/tiref.txt kats/hqc-1/tinew.txt
	diff -b $^

kats1diff: kats/hqc-1/katsref.txt kats/hqc-1/katsnew.txt
	diff -b $^

kats/hqc-1/tinew.txt: obj1/test_intermediates
	obj1/test_intermediates >$@

kats/hqc-1/katsnew.txt: obj1/test_kat
	obj1/test_kat >$@

obj1/test_intermediates: src/*.ads src/*.adb hqc.gpr
	gprbuild -Phqc -XHQC_PARAM=1 $(COMPSWITCHES)

obj1/test_kat: src/*.ads src/*.adb hqc.gpr
	gprbuild -Phqc -XHQC_PARAM=1 $(COMPSWITCHES)

# Intermediate values KAT for HQC-3
ti3diff: kats/hqc-3/tiref.txt kats/hqc-3/tinew.txt
	diff -b $^

kats3diff: kats/hqc-3/katsref.txt kats/hqc-3/katsnew.txt
	diff -b $^

kats/hqc-3/tinew.txt: obj3/test_intermediates
	obj3/test_intermediates >$@

kats/hqc-3/katsnew.txt: obj3/test_kat
	obj3/test_kat >$@

obj3/test_intermediates: src/*.ads src/*.adb hqc.gpr
	gprbuild -Phqc -XHQC_PARAM=3 $(COMPSWITCHES)

obj3/test_kat: src/*.ads src/*.adb hqc.gpr
	gprbuild -Phqc -XHQC_PARAM=3 $(COMPSWITCHES)

# Intermediate values KAT for HQC-5
ti5diff: kats/hqc-5/tiref.txt kats/hqc-5/tinew.txt
	diff -b $^

kats5diff: kats/hqc-5/katsref.txt kats/hqc-5/katsnew.txt
	diff -b $^

kats/hqc-5/tinew.txt: obj5/test_intermediates
	obj5/test_intermediates >$@

kats/hqc-5/katsnew.txt: obj5/test_kat
	obj5/test_kat >$@

obj5/test_intermediates: src/*.ads src/*.adb hqc.gpr
	gprbuild -Phqc -XHQC_PARAM=5 $(COMPSWITCHES)

obj5/test_kat: src/*.ads src/*.adb hqc.gpr
	gprbuild -Phqc -XHQC_PARAM=5 $(COMPSWITCHES)

clean:
	gprclean -Phqc -XHQC_PARAM=1 2>/dev/null; true
	gprclean -Phqc -XHQC_PARAM=3 2>/dev/null; true
	gprclean -Phqc -XHQC_PARAM=5 2>/dev/null; true
	rm -f kats/hqc-1/tinew.txt kats/hqc-1/katsnew.txt
	rm -f kats/hqc-3/tinew.txt kats/hqc-3/katsnew.txt
	rm -f kats/hqc-5/tinew.txt kats/hqc-5/katsnew.txt

.PHONY: all binaries results diffs clean
.PHONY: hqc-1-binaries hqc-3-binaries hqc-5-binaries
.PHONY: ti1diff ti3diff ti5diff kats1diff kats3diff kats5diff
.PHONY: proofall proof1 proof3 proof5
