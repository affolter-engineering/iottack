// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Nicolas Gabriel Cotti

//! Unsafe bindings from the libsigrok and libsigrokdecoder libraries,
//! automatically created with bindgen.
//!
//! To build and execute the code, the library must have been installed in
//! a "visible path".
//!
//! Supported paths are:
//! * `/usr/lib` and `/usr/include`.
//! * `/usr/local/lib` and `/usr/local/include`.
//! * `/usr/lib/<arch>-<os>-<libc>` and `/usr/include/<lib_name>`.
//! * Any path set in the `LD_LIBRARY_PATH` env. variable.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(missing_docs)]

pub mod sigrok {
    include!(concat!(env!("OUT_DIR"), "/sigrok_bindings.rs"));
}

pub mod sigrokdecode {
    include!(concat!(env!("OUT_DIR"), "/sigrokdecode_bindings.rs"));
}
