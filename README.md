# strand

Strand is a cryptographic library for use in secure online voting protocols. 

## Primitives

The following primitives are implemented

* ElGamal and exponential ElGamal

* [Threshold distributed ElGamal](https://members.loria.fr/VCortier/files/Papers/WPES2013.pdf)

* [Proofs of Restricted Shuffles](http://www.csc.kth.se/~terelius/TeWi10Full.pdf)

* [A Commitment-Consistent Proof of a Shuffle](https://eprint.iacr.org/2011/168.pdf)

* [Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets](https://www.ifca.ai/fc17/voting/papers/voting17_HLKD17.pdf)

Shuffle proofs have been independently verified

* [Did you mix me? Formally Verifying Verifiable Mix Nets in Electronic Voting](https://eprint.iacr.org/2020/1114.pdf) using [this](https://github.com/nvotes/secure-e-voting-with-coq/tree/master/OCamlBraid).

## Dependencies

The library supports pluggable [discrete log](https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption) backends, there are currently three:

* Curve25519 using the [ristretto group](https://ristretto.group/) via the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) library.
* [Standard multiplicative groups](https://en.wikipedia.org/wiki/Schnorr_group) via the [rug](https://crates.io/crates/rug) arbitrary-precision library, backed by [gmp](https://gmplib.org/).
* [Standard multiplicative groups](https://en.wikipedia.org/wiki/Schnorr_group) via the pure rust [num-bigint](https://crates.io/crates/num-bigint) arbitrary-precision library.

Other significant dependencies:

* Compute intensive portions are parallelized using [rayon](https://github.com/rayon-rs/rayon).
* Symmetric encryption is provided by [RustCrypto](https://github.com/RustCrypto/block-ciphers).

## wasm test

See [here](https://github.com/sequentech/strand/tree/main/src/wasm/test).

## benchmarks

See [here](https://github.com/sequentech/strand/tree/main/benches).
