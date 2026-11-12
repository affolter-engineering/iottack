{
  description = "Virtual CAN bus simulator for IoTtack testing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        simulator = pkgs.rustPlatform.buildRustPackage {
          pname = "iottack-target-can";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          meta = with pkgs.lib; {
            description = "Virtual CAN bus simulator for IoTtack testing";
            license = licenses.mit;
            platforms = platforms.linux;
          };
        };
      in {
        # nix run . -- --iface vcan0
        apps.default = {
          type = "app";
          program = "${simulator}/bin/can-simulator";
        };

        # nix build
        packages.default = simulator;

        # nix develop  (Rust toolchain + iproute2 for ip link set vcan0 up)
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            iproute2
          ];
        };
      });
}
