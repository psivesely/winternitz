# winternitz

WARNING: this is a (just) functioning, but incomplete, unaudited, and largely
bereft of testing implementation. You should not use this yet.

A standalone version of the WOTS-T signature scheme [[1]](#references) [[2]](#references). As far as I know this is the only standalone implementation, and the only other implementations are integrated in XMSS-T and SPHINCS+.

The implementation parameters are all fixed for now, but will be flexible in the future. Using a 512-bit public seed, a 512-bit secret key seed, and a 128-bit unique address, you can derive a unique WOTS-T keypair for use in a hash-based signature scheme like XMSS-T or SPHINCS+.

Keyed BLAKE2b serves both as the PRF and the cryptographic hash function called for by the scheme. ChaCha20 may replace BLAKE2b as the PRF once the repo is in a state where I can do proper benchmarks.

The substructure address generation functions are just dummy functions for now
as I decide how to make standalone versions. (They appear very integrated in
the larger hash-based signature scheme in the XMSS-T reference implementation of
WOTS-T).

### References

[1] Mitigating Multi-Target Attacks in Hash-based Signatures
https://eprint.iacr.org/2015/1256.pdf

[2] W-OTS+– Shorter Signatures for Hash-Based Signature Schemes
https://eprint.iacr.org/2017/965.pdf
