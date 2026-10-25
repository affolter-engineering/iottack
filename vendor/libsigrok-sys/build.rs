// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Nicolas Gabriel Cotti

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Contains the path to the library and header
#[derive(Debug)]
struct LibPaths {
    dynamic_lib: Option<PathBuf>,
    static_lib: Option<PathBuf>,
    header: Option<PathBuf>,
}

/// Creates a `wrapper.h` header file that includes all header files
/// listed in the "headers" input
fn merge_headers(lib_name: &str, headers: Vec<&str>) -> PathBuf {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let wrapper = lib_name.to_string() + "_wrapper.h";
    let wrapper_path = out_path.join(wrapper);

    let mut wrapper = File::create(&wrapper_path).unwrap();

    for header in headers {
        wrapper
            .write_all(format!("#include \"{}\"\n", header).as_bytes())
            .unwrap();
    }

    wrapper_path
}

/// Checks whether the library is already installed in your system.
///
/// `lib_name` is the name of the library without the "lib" prefix, like
/// `lib<lib_name>.so`.
/// `headers` is a vector which contains all headers required by the library.
/// To generate the bindgen, a single "wrapper.h" header will be created
/// which will contain `#include <header.h>` statements to all files listed.
///
/// Returns the library and wrapper header paths as `Option<PathBuf>`,
/// which may be `None` if they couldn't be found.
///
/// The library is searched in common directories, plus the env.
/// variable "LD_LIBRARY_PATH"
fn get_system_lib_paths(lib_name: &str, headers: Vec<&str>) -> LibPaths {
    // Returns something like "x86_64-unknown-linux-gnu", i.e.
    // <arch>-<vendor>-<os>-<libc>
    let target = std::env::var("TARGET").unwrap();

    // Remove <vendor> from target tuple
    let target = target
        .split('-')
        .enumerate()
        .filter_map(|(i, x)| (i != 1).then_some(x))
        .collect::<Vec<_>>()
        .join("-");

    let mut possible_lib_paths: Vec<PathBuf> = vec![
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/lib").join(target),
    ];

    println!("{:?}", possible_lib_paths);

    let header_name = merge_headers(lib_name, headers);

    // The user may provide these env. variable to search for the library
    let env_vars = ["LD_LIBRARY_PATH"];

    for env_var in env_vars {
        if let Some(dirs) = env::var_os(env_var) {
            // The env. variable may have multiple dirs separated by semicolons
            for dir in dirs.to_string_lossy().split(":") {
                let absolute_path_from_env =
                    PathBuf::from(&dir).canonicalize().unwrap_or_else(|e| {
                        panic!("Path in {env_var}={:?} does not exists. Error: {e}", dir);
                    });
                possible_lib_paths.insert(0, absolute_path_from_env.clone());
            }
        };
    }

    let dyn_lib: String = format!("lib{}.so", lib_name);
    let static_lib: String = format!("lib{}.a", lib_name);

    let possible_dynamic_libs: Vec<PathBuf> = possible_lib_paths
        .clone()
        .into_iter()
        .map(|path| path.join(&dyn_lib))
        .collect();
    let possible_static_libs: Vec<PathBuf> = possible_lib_paths
        .into_iter()
        .map(|path| path.join(&static_lib))
        .collect();

    let dynamic_lib = possible_dynamic_libs.into_iter().find(|path| path.exists());
    let static_lib = possible_static_libs.into_iter().find(|path| path.exists());

    LibPaths {
        dynamic_lib: dynamic_lib,
        static_lib: static_lib,
        header: Some(header_name),
    }
}

fn generate_bindings(
    lib_name: &str,
    headers: Vec<&str>,
    feature_static: bool,
    bindings_file: &str,
) {
    let lib_paths = get_system_lib_paths(lib_name, headers);

    if (feature_static && lib_paths.static_lib.is_none())
        || (!feature_static && lib_paths.dynamic_lib.is_none())
    {
        panic!(
            r#"Couldn't find system library {lib_name} installed.
Please, do one of the following:
- Install the sigrok library.
- Set the "LD_LIBRARY_PATH" environment variable to the path where the library is installed.
See the crate documentation for details.
"#
        );
    }

    let lib_dir = match feature_static {
        true => lib_paths.static_lib.as_ref().unwrap().parent().unwrap(),
        false => lib_paths.dynamic_lib.as_ref().unwrap().parent().unwrap(),
    }
    .to_string_lossy();

    // Tell cargo to look for shared libraries in the specified directory
    // Similar to "-L" flag
    println!("cargo:rustc-link-search={}", lib_dir);

    // Add the library dir to the run-time search-path (only useful for this crate)
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir);

    // Tell cargo to tell rustc to link the system ftd2xx shared library.
    // Similar to "-l" flag
    if feature_static {
        println!("cargo:rustc-link-lib=static={}", lib_name);
    } else {
        println!("cargo:rustc-link-lib=dylib={}", lib_name);
    }

    let include_paths: Vec<PathBuf> =
        match pkg_config::probe_library(format!("lib{}", lib_name).as_ref()) {
            Ok(lib) => lib.include_paths,
            Err(_) => Vec::new(),
        };

    let mut include_args: Vec<String> = Vec::new();
    for inc in include_paths {
        include_args.push(format!("-I{}", inc.to_string_lossy()));
    }

    let bindings = bindgen::Builder::default()
        .header(lib_paths.header.clone().unwrap().to_string_lossy())
        .clang_args(include_args)
        .allowlist_file(format!(".*{}.*", lib_name))
        .allowlist_file(".*glib.*")
        .allowlist_type("sr_channel")
        // Opaque GLib types do not have layouts available to bindgen.
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join(bindings_file))
        .expect("Couldn't write bindings!");
}

fn main() {
    let feature_static = false;

    let sigrok_lib_name: &str = "sigrok";
    let sigrok_headers: Vec<&str> = vec!["libsigrok/libsigrok.h"];
    let sigrok_bindings: &str = "sigrok_bindings.rs";

    let decoder_lib_name: &str = "sigrokdecode";
    let decoder_headers: Vec<&str> = vec!["libsigrokdecode/libsigrokdecode.h"];
    let decoder_bindings: &str = "sigrokdecode_bindings.rs";

    println!("cargo:rerun-if-env-changed=LD_LIBRARY_PATH");

    generate_bindings(
        sigrok_lib_name,
        sigrok_headers,
        feature_static,
        sigrok_bindings,
    );

    generate_bindings(
        decoder_lib_name,
        decoder_headers,
        feature_static,
        decoder_bindings,
    );
}
