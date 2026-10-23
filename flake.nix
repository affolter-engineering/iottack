{
  description = "iottack - IoT protocol and implementation testing framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.stable.latest.default;
        # bindgen needs libclang and the glibc headers.
        sharedBuildAttrs = {
          nativeBuildInputs = with pkgs; [
            gcc
            pkg-config
            llvmPackages.libclang.lib
          ];
          buildInputs = with pkgs; [ libsigrok libsigrokdecode glib dbus ];
          LD_LIBRARY_PATH = "${pkgs.libsigrok}/lib:${pkgs.libsigrokdecode}/lib:${pkgs.glib.out}/lib";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.glibc.dev}/include -isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.llvmPackages.libclang.version}/include";
        };
      in {
        # `nix develop` - drop into dev shell
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            gcc
            pkg-config
            libsigrok
            libsigrokdecode
            glib
            dbus
            llvmPackages.libclang.lib
          ];
          LD_LIBRARY_PATH = "${pkgs.libsigrok}/lib:${pkgs.libsigrokdecode}/lib:${pkgs.glib.out}/lib";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.glibc.dev}/include -isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.llvmPackages.libclang.version}/include";
          RUST_BACKTRACE = "1";
        };

        # `nix build` - produce the binary
        packages.default = pkgs.rustPlatform.buildRustPackage ({
          pname = "iottack";
          version = "0.2.6";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          meta = with pkgs.lib; {
            description = "IoT protocol testing framework";
            license = licenses.mit;
            platforms = platforms.linux ++ platforms.darwin;
          };
        } // sharedBuildAttrs);

        # `nix flake check` - build and run cargo test
        checks.default = pkgs.rustPlatform.buildRustPackage ({
          pname = "iottack";
          version = "0.2.6";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = true;
        } // sharedBuildAttrs);

        # `nix run` - run directly
        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };
      });
}
