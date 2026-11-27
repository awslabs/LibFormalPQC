//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! With the `bench` feature, compiles the cycle counter in SLH/hal/hal.c
//! (from mlkem-native) into a static library for the benchmark program.
//! Without it, does nothing. Uses the system C compiler ($CC, or cc), so
//! no build dependencies are needed.
//!
//! This is build tooling: it uses std, and is not verified by Verus.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().unwrap_or_else(|e| panic!("can't run {:?}: {}", cmd, e));
    assert!(status.success(), "{:?} failed", cmd);
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var_os("CARGO_FEATURE_BENCH").is_none() {
        return;
    }
    let hal = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../hal");
    println!("cargo:rerun-if-changed={}", hal.join("hal.c").display());
    println!("cargo:rerun-if-changed={}", hal.join("hal.h").display());
    println!("cargo:rerun-if-env-changed=CC");

    //  The cycle counter to use. See SLH/hal/README.md
    let counter = match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "macos" => "-DMAC_CYCLES",
        "linux" => "-DPERF_CYCLES",
        _ => "-DNO_CYCLES",
    };
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out.join("hal.o");
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    run(Command::new(&cc).args(["-O2", "-c", counter, "-o"]).arg(&obj).arg(hal.join("hal.c")));
    run(Command::new("ar").arg("crs").arg(out.join("libhal.a")).arg(&obj));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=hal");
}
