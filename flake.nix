# SPDX-FileCopyrightText: 2021 Eduardo Robles <edulix@sequentech.io>
#
# SPDX-License-Identifier: AGPL-3.0-only
{
  description = "Flake to test rust code";

  inputs.rust-overlay.url = "github:oxalica/rust-overlay";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let 
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { 
          inherit system overlays;
        };
        stdenv = pkgs.clangStdenv;
        rust-wasm = pkgs
          .rust-bin
          .nightly
          ."2022-04-07"
          .default
          .override {
              extensions = [ "rust-src" ];
              targets = [ "wasm32-unknown-unknown" ];
          }
        ;
        rust-system = pkgs
          .rust-bin
          .nightly
          ."2022-04-07"
          .default
          .override {
              extensions = [ "rust-src" ];
          }
        ;
      in rec {
        packages.strand-wasm = pkgs.rustPlatform.buildRustPackage {
          pname = "strand-wasm";
          version = "0.0.3";
          src = ./.;
          nativeBuildInputs = [
            rust-wasm
            pkgs.nodePackages.npm
            pkgs.wasm-pack
            pkgs.wasm-bindgen-cli
          ];
          buildPhase = ''
            echo 'Build: wasm-pack build'
            wasm-pack build --mode no-install --out-name index --release --target web --features=wasmtest
          '';
          installPhase = "
            # set HOME temporarily to fix npm pack
            mkdir -p $out/temp_home
            export HOME=$out/temp_home
            echo 'Install: wasm-pack pack'
            wasm-pack -v pack .
            rm -Rf $out/temp_home
            cp pkg/strand-*.tgz $out
            ";

            # see https://github.com/NixOS/nixpkgs/blob/master/doc/languages-frameworks/rust.section.md#importing-a-cargolock-file-importing-a-cargolock-file
            cargoLock = let
                fixupLockFile = path: (builtins.readFile path);
            in {
                lockFileContents = fixupLockFile ./Cargo.lock.copy;
            };
            postPatch = ''
                cp ${./Cargo.lock.copy} Cargo.lock
            '';
        };
        packages.strand-system = pkgs.rustPlatform.buildRustPackage {
          pname = "strand-system";
          version = "0.0.2";
          src = ./.;
          nativeBuildInputs = [
            rust-system
          ];

            # see https://github.com/NixOS/nixpkgs/blob/master/doc/languages-frameworks/rust.section.md#importing-a-cargolock-file-importing-a-cargolock-file
            cargoLock = let
                fixupLockFile = path: (builtins.readFile path);
            in {
                lockFileContents = fixupLockFile ./Cargo.lock.copy;
            }; 
            postPatch = ''
                cp ${./Cargo.lock.copy} Cargo.lock
            '';
        }; 
        defaultPackage = self.packages.${system}.strand-wasm;

        # configure the dev shell
        devShell = (
          pkgs.mkShell.override { stdenv = pkgs.clangStdenv; }
        ) { 
          buildInputs = 
            defaultPackage.nativeBuildInputs ++
            [ pkgs.bash ]; 
        };
      }
    );
}
