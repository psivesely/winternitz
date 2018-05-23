# winternitz

WARNING: this is a (just) functioning, but incomplete, unaudited, and largely
bereft of testing implementation. You should not use this yet.

A standalone version of the WOTS-T signature scheme [[1]](#references) [[2]](#references). As far as I know this is the only standalone implementation, and the only other implementations are integrated in XMSS-T and SPHINCS+.

## Implementation

The implementation parameters are all fixed for now, but will be flexible in the future. Using a 512-bit public seed, a 512-bit secret key seed, and a 128-bit unique address, you can derive a unique WOTS-T keypair for use in a hash-based signature scheme like XMSS-T or SPHINCS+.

Keyed BLAKE2b serves both as the PRF and the cryptographic hash function called for by the scheme. ChaCha20 may replace BLAKE2b as the PRF once the repo is in a state where I can do proper benchmarks.

The substructure address generation functions are just dummy functions for now as I decide how to make standalone versions. (They appear very integrated in the larger hash-based signature scheme in the XMSS-T reference implementation of WOTS-T).

## Bug Reporting

*winternitz* has a **full disclosure** policy for vulnerabilities. **Please do NOT attempt to report any security vulnerability in this code privately to anybody.** Since *winternitz* intends to protect against adversaries with vast resources, it is assumed that any vulnerabilities are already known to attackers. Accordingly, this project prioritizes disclosing vulnerabilities to users over hiding vulnerabilities from adversaries.

To report a vulnerability: please open an issue on the [public GitHub issue tracker](https://github.com/nvesely/winternitz/issues). If you believe the issue is serious, I would appreciate it if you also [email me](mailto:fowlslegs@riseup.net) (optionally using [PGP key 0x8CBD5ED9D835B0E1](https://keybase.io/fowlslegs)) separately with a link to the GitHub issue so that I can prioritize it above other issues.

Vulnerability research is an important part of making *winternitz* a high-quality library. Please find bugs!


## Contributing

Please file an issue for feedback and discussion before making a PR that is more than trivial. This will save us both time as the design goals of this library necessitate a very conservative approach to adding new code or features.

To illustrate, one such aim is to keep the codebase as small and easy to audit as possible. A PR that, for example, would add the ability to specify the hash function and/or PRF used would be rejected; I believe a single secure and fast choice should remain hard-coded.

If making a PR it will need to be properly formatted and linted to pass CI and be merged. So that only the code a PR contributes get linted (and not other files due to updates in the tools used), I have pinned versions of Rust nightly, `rustfmt`, and `clippy` that should be used. I have included in the `Makefile` commands to ease the installation and execution of these correct versions of what's needed, as well as to execute these tools with the correct options. To do the initial install ensure `rustup` is installed (or run `make install-rustup`). Then run the following commands:

```
make install-pinned-nightly
make install-dev-tools
```

These tools will be updated every couple of months or so. Running these two commands again will get everything updated.

To actually run `clippy` (resp., `rustfmt`) use the command `make run-clippy` (resp., `make run-rustfmt`) or to run both you can use `make run-lints`.

## License

The GNU LGPLv3. See [LICENSE](LICENSE).

### References

[1] Mitigating Multi-Target Attacks in Hash-based Signatures
https://eprint.iacr.org/2015/1256.pdf

[2] W-OTS+– Shorter Signatures for Hash-Based Signature Schemes
https://eprint.iacr.org/2017/965.pdf
