importScripts("../../../pkg/strand.js");
const { test, bench } = wasm_bindgen;

wasm_bindgen("../../../pkg/strand_bg.wasm").then(_ => {
    var parameters = {}
    location.search.slice(1).split("&").forEach( function(key_value) { var kv = key_value.split("="); parameters[kv[0]] = kv[1]; });
    postMessage(`Initialized wasm`);
    test();
    postMessage(' ');
    if(parameters['bench'] === 'true') {
        bench(10);
    }
    postMessage(' ');
    postMessage('ok');
})