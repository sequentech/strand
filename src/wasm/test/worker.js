import * as pkg from "../../../pkg_t/strand.js";
pkg.default().then(_ => {
    var parameters = {}
    location.search.slice(1).split("&").forEach( function(key_value) { var kv = key_value.split("="); parameters[kv[0]] = kv[1]; });
    postMessage(`Initialized wasm`);
    pkg.test();
    postMessage(' ');
    if(parameters['bench'] === 'true') {
        pkg.bench(10);
    }
    postMessage(' ');
    postMessage('ok');
})