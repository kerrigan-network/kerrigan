# drone-vecgen

Regenerates the golden wire vectors for the `CDroneRegTx` drone-registration
special tx: `src/test/data/drone_wire_vectors.json` (consumed by
`src/test/inference_wire_tests.cpp`).

The generator implements the exact C++ consensus payload serialization + the
BLS min_sig signing scheme (blst, DST `..._KRGN_REG_V1_`), with deterministic
keys so the vectors are reproducible from source alone.

    cargo run --offline -- verify-old src/test/data/drone_wire_vectors.json   # validate against the committed set
    cargo run --offline -- generate   > src/test/data/drone_wire_vectors.json # regenerate

`drone_wire_vectors.OLD.json` is the pre-model-tier vector set, kept for the
`verify-old` cross-check.
