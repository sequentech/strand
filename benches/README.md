<!--
SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
SPDX-FileCopyrightText: 2022 Eduardo Robles <edu@sequentech.io>

SPDX-License-Identifier: AGPL-3.0-only
-->
## Benchmarks

First make sure to enable the benchmark in Cargo.toml as follows:

`bench = true`

in the corresponding `[[bench]]` section.

### Encryption

* `cargo bench encrypt`
* `cargo bench encrypt --features=rug`
* `cargo bench encrypt --features=rayon`

### Shuffling

* `cargo bench shuffle`
* `cargo bench shuffle --features=rug`
* `cargo bench shuffle --features=rayon`