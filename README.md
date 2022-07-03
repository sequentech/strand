<!--
SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
SPDX-FileCopyrightText: 2022 Eduardo Robles <edu@nsequentech.io>

SPDX-License-Identifier: AGPL-3.0-only
-->
# strand
[![Build Status][build-badge]][build-link]
[![codecov][codecov-badge]][codecov]
[![Dependency status][dependencies-badge]][dependencies-link]
[![License][license-badge]][license-link]

Strand is a cryptographic library for use in secure online voting protocols. 

## Primitives

The following primitives are implemented

* ElGamal and exponential ElGamal encryption.

* Fixed distributed and [threshold distributed ElGamal](https://members.loria.fr/VCortier/files/Papers/WPES2013.pdf).

* [Wikstrom](http://www.csc.kth.se/~terelius/TeWi10Full.pdf) [shuffle](https://eprint.iacr.org/2011/168.pdf) [proofs](https://www.ifca.ai/fc17/voting/papers/voting17_HLKD17.pdf).

* Schnorr and Chaum-Pedersen zero knowledge proofs.

Shuffle proofs have been independently verified

* [Did you mix me? Formally Verifying Verifiable Mix Nets in Electronic Voting](https://eprint.iacr.org/2020/1114.pdf) using [this](https://github.com/nvotes/secure-e-voting-with-coq/tree/master/OCamlBraid).

## Group backends

The library supports pluggable [discrete log](https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption) backends, there are currently three:

* Curve25519 using the [ristretto group](https://ristretto.group/) via the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) library.
* [Standard multiplicative groups](https://en.wikipedia.org/wiki/Schnorr_group) via the [rug](https://crates.io/crates/rug) arbitrary-precision library, backed by [gmp](https://gmplib.org/).
* [Standard multiplicative groups](https://en.wikipedia.org/wiki/Schnorr_group) via the [num-bigint](https://crates.io/crates/num-bigint) arbitrary-precision library, in pure rust.

## Significant dependencies

* Compute intensive portions are parallelized using [rayon](https://github.com/rayon-rs/rayon).
* Symmetric encryption using [RustCrypto](https://github.com/RustCrypto/block-ciphers).
* Serialization of intermediate byte trees using [bincode](https://crates.io/crates/bincode) and serde.
* Randomness is sourced from [rand::rngs::OsRng](https://docs.rs/rand/latest/rand/rngs/struct.OsRng.html), in wasm builds [getrandom](https://crates.io/crates/getrandom) is backed by [Crypto.getRandomValues](https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues)

## Continuous Integration

There are multiple checks executed through the usage of Github Actions to verify
the health of the code when pushed:
1. **Compiler warning/errors**: checked using `cargo check` and 
`cargo check ---tests`. Use `cargo fix` and `cargo fix --tests` to fix the 
issues that appear.
2. **Unit tests**: check that all unit tests pass using `cargo test`.
3. **Code style**: check that the code style follows standard Rust format, using
`cargo fmt -- --check`. Fix it using `cargo fmt`.
4. **Code linting**: Lint that checks for common Rust mistakes using 
`cargo clippy`. You can try to fix automatically most of those mistakes using
`cargo clippy --fix -Z unstable-options`.
5. **Code coverage**: Detects code coverage with [cargo-tarpaulin] and pushes
the information (in master branch) to [codecov].
6. **License compliance**: Check using [REUSE] for license compliance within
the project, verifying that every file is REUSE-compliant and thus has a 
copyright notice header.
7. **Dependencies scan**: Audit dependencies for security vulnerabilities in the
[RustSec Advisory Database], unmaintained dependencies, incompatible licenses
and banned packages using [cargo-deny]. Use `cargo deny fix` or
`cargo deny --allow-incompatible` to try to solve the detected issues.
8. **Benchmark performance**: Check benchmark performance and alert on
regressions using `cargo bench` and [github-action-benchmark].

## Development environment

strand uses the [Nix Package Manager](https://nixos.org/) as its package
builder. To build strand, **first [install Nix](https://nixos.org/)** correctly
in your system.

After you have installed Nix, enter the development environment with:

```bash
nix develop
```

## Updating Cargo.toml

Use the following [cargo-edit] command to upgrade dependencies to latest
available version. This can be done within the `nix develop` environment:

```bash
cargo upgrade -Z preserve-precision
```

## building

```cargo build```

### Build with parallelism

Uses rayon's parallel collections for compute intensive operations

```cargo build --features=rayon```

## unit tests

```cargo test```

## wasm test

See [here](https://github.com/sequentech/strand/tree/main/src/wasm/test).

## benchmarks

See [here](https://github.com/sequentech/strand/tree/main/benches).

[cargo-deny]: https://github.com/EmbarkStudios/cargo-deny
[cargo-edit]: https://crates.io/crates/cargo-edit
[codecov]: https://codecov.io/
[REUSE]: https://reuse.software/
[tarpaulin]: https://github.com/xd009642/tarpaulin
[github-action-benchmark]: https://github.com/benchmark-action/github-action-benchmark
[build-badge]: https://github.com/sequentech/strand/workflows/CI/badge.svg?branch=master&event=push
[build-link]: https://github.com/sequentech/strand/actions?query=workflow%3ACI
[codecov-badge]: https://codecov.io/gh/sequentech/strand/branch/master/graph/badge.svg
[license-badge]: https://img.shields.io/github/license/sequentech/strand?label=license
[license-link]: https://github.com/sequentech/strand/blob/master/LICENSE
[dependencies-badge]: https://deps.rs/repo/github/sequentech/strand/status.svg
[dependencies-link]: https://deps.rs/repo/github/sequentech/strand
