## Test wasm build

* install [webpack](https://rustwasm.github.io/wasm-pack/installer/)
* `wasm-pack build --out-name index --release --target web --features=wasmtest`
* `python3 src/wasm/test/serve.py`
* http://localhost:8080/src/wasm/test/test.html

## Test wasm build with no workers

* install [webpack](https://rustwasm.github.io/wasm-pack/installer/)
* `wasm-pack build --out-name index --release --target web --features=wasmtest`
* `python3 src/wasm/test/serve.py`
* http://localhost:8080/src/wasm/test/test_noworkers.html

### Test wasm build with multithreading

* install [webpack](https://rustwasm.github.io/wasm-pack/installer/)
* Build with [multithreading](https://github.com/GoogleChromeLabs/wasm-bindgen-rayon)
```
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \ 
rustup run nightly-2022-04-07 wasm-pack build --out-name index --release  --release --target web \ 
--features=wasmtest,wasmrayon -- -Z build-std=panic_abort,std
```
* `python3 src/wasm/test/serve.py`
* http://localhost:8080/src/wasm/test/test.html?threaded=true

In order for this test to work the browser must have [cross origin isolation](https://web.dev/cross-origin-isolation-guide/) enabled. This requires sending the appropriate headers (see serve.py)
and cannot work without https unless testing on localhost.
