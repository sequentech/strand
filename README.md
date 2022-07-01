<!--
SPDX-FileCopyrightText: 2022 David Ruescas <david@nvotes.com>
SPDX-FileCopyrightText: 2022 Eduardo Robles <edu@nvotes.com>

SPDX-License-Identifier: AGPL-3.0-only
-->
# strand

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
5. **Code coverage**: Detects code coverage with [grcov] and pushes the 
information (in master branch) to [codecov].
1. **License compliance**: Check using [REUSE] for license compliance within
the project, verifying that every file is REUSE-compliant and thus has a 
copyright notice header.

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
