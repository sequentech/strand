# SPDX-FileCopyrightText: 2021 Eduardo Robles <edulix@sequentech.io>
#
# SPDX-License-Identifier: AGPL-3.0-only
{
  description = "Flake to test rust code";

  inputs.rust-overlay.url = "github:oxalica/rust-overlay";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-21.11";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let 
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { 
          inherit system overlays;
        };
        stdenv = pkgs.clangStdenv;
        rust-nightly = pkgs
          .rust-bin
          .nightly
          ."2022-04-07"
          .default
          .override {
              extensions = [ "rust-src" ];
              targets = [ "wasm32-unknown-unknown" ];
          }
        ;
      in rec {
        defaultPackage = pkgs.rustPlatform.buildRustPackage {
          pname = "strand";
          version = "0.0.1";
          src = ./.;
          nativeBuildInputs = [
            rust-nightly
            pkgs.nodePackages.npm
            pkgs.wasm-pack
            pkgs.wasm-bindgen-cli
          ];
          buildPhase = ''
            echo 'Build: wasm-pack build'
            wasm-pack build --mode no-install --out-name index --release --target web --features=wasm
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

          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };

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
