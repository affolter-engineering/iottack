{
  description = "BACnet/IP test simulator for IoTtack";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        bacpypes3 = pkgs.python3Packages.buildPythonPackage rec {
          pname = "bacpypes3";
          version = "0.0.110";
          pyproject = true;
          src = pkgs.fetchPypi {
            inherit pname version;
            hash = "sha256-/RMK5YRKNwooEQAR8UquBGVJOdMl4mynEUezm7TL2UI=";
          };
          build-system = [ pkgs.python3Packages.hatchling ];
        };

        pythonEnv = pkgs.python3.withPackages (ps: [
          bacpypes3
        ]);

        simulatorScript = pkgs.writeShellApplication {
          name = "bacnet-simulator";
          text = ''
            exec ${pythonEnv}/bin/python ${./simulator.py} "$@"
          '';
        };
      in {
        # nix run
        apps.default = {
          type = "app";
          program = "${simulatorScript}/bin/bacnet-simulator";
        };

        # nix build
        packages.default = simulatorScript;

        # nix develop  (drop into a shell with bacpypes3 available)
        devShells.default = pkgs.mkShell {
          packages = [ pythonEnv ];
        };
      });
}
