{
  description = "Modbus/TCP test simulator for IoTtack";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        pythonEnv = pkgs.python3.withPackages (ps: [
          ps.pymodbus
        ]);

        simulatorScript = pkgs.writeShellApplication {
          name = "modbus-simulator";
          text = ''
            exec ${pythonEnv}/bin/python ${./simulator.py} "$@"
          '';
        };
      in {
        # nix run
        apps.default = {
          type = "app";
          program = "${simulatorScript}/bin/modbus-simulator";
        };

        # nix build
        packages.default = simulatorScript;

        # nix develop  (drop into a shell with pymodbus available)
        devShells.default = pkgs.mkShell {
          packages = [ pythonEnv ];
        };
      });
}
