# strand

## wasm test
* `wasm-pack build --release --target web --features=wasmtest`
* `python3 src/wasm/test/serve.py`
* http://localhost:8080/src/wasm/test/test.html
### rayon (broken)
* https://github.com/GoogleChromeLabs/wasm-bindgen-rayon
*  .cargo/config
    [target.wasm32-unknown-unknown]
    rustflags = ["-C", "target-feature=+atomics,+bulk-memory,+mutable-globals"]
    
    [unstable]
    build-std = ["panic_abort", "std"]
    
* rust-toolchain `nightly-2022-04-07`
* `wasm-pack build --release --target web --features=wasmrayon,wasmtest`
