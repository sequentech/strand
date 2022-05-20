import init, {ex} from "../../../pkg/strand.js";
init()
.then(() => {
    const bytes = new Uint8Array([1,99,226,99]);
    let obj = {
        Leaf: [1, 2, 3, 4]
    }
    let ret = ex(bytes);
    console.dir(ret);
});