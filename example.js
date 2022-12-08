/**
SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
SPDX-FileCopyrightText: 2022 Eduardo Robles <edu@sequentech.io>

SPDX-License-Identifier: AGPL-3.0-only
*/
import init, {ex} from "../../../pkg/index.js";
init()
.then(() => {
    const bytes = new Uint8Array([1,99,226,99]);
    let obj = {
        Leaf: [1, 2, 3, 4]
    }
    let ret = ex(bytes);
    console.dir(ret);
});