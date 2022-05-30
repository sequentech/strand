await import("./fd.js");
let pkg = await import("../../../pkg/strand.js");
pkg.default().then(_ => {
    postMessage(`Initialized wasm`);
    postMessage('Cross origin isolated: ' + self.crossOriginIsolated);
    var go = function() {
        pkg.test();
        postMessage(' ');
        pkg.bench();
        postMessage(' ');
        postMessage('ok');
    }
    wasmFeatureDetect.threads().then(threads => {
        if (threads && pkg.initThreadPool) {
            postMessage('Thread pool supported, initThreadPool with conc = ' + navigator.hardwareConcurrency + '..');
            pkg.initThreadPool(navigator.hardwareConcurrency).then(_ => {
                postMessage('Thread pool initialized');
                go();
            })
        }
        else {
            postMessage('Thread pool NOT supported');
            go();    
        }
    });
})