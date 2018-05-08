//N*L - g! *winternitz* implements one-time hash-based signatures using the
//! W-OTS+ signature scheme.

// `#[derive(...)]` uses `#[allow(unused_qualifications)]` internally.
#![deny(unused_qualifications)]
// `missing_debug_implementations` requires manual implementation of of `fmt::Debug`
#![forbid(
    trivial_casts, trivial_numeric_casts, unstable_features, unused_import_braces,
    unused_extern_crates, non_upper_case_globals, unused_parens, non_camel_case_types, box_pointers,
    anonymous_parameters, legacy_directory_ownership, variant_size_differences, missing_docs,
    warnings, missing_copy_implementations, unused_results
)]
#![no_std]

extern crate libsodium_sys;
extern crate sodiumoxide;
extern crate subtle;

use libsodium_sys::crypto_generichash_blake2b;
use sodiumoxide::randombytes::randombytes_into;
use subtle::{Choice, ConstantTimeEq};

const N: usize = 512 / 8; // Main security parameter
const M: usize = 512 / 8; // Message digest length
const A: usize = 128 / 8; // Address length
const W: usize = 16; // Winternitz parameter
const L1: usize = 128; // Length of the base-`W` representation of a message of length `M`.
const L2: usize = 3; // Length of the base-`W` checksum of a base-`W` message of length `L1`.
const L: usize = L1 + L2; // Number of function chains

/// The global secret key seed
pub type SecKeySeed = [u8; N];

/// Generates a random secret key seed
pub fn new_sec_key_seed() -> SecKeySeed {
    let mut out = [0; N];
    randombytes_into(&mut out);
    out
}

/// The global public seed
pub type PubSeed = [u8; N];

/// Generates a random public seed
pub fn new_pub_seed() -> PubSeed {
    new_sec_key_seed()
}

/// A WOTS-T keypair address within a tree, or the
pub type Addr = [u8; A];

/// A one-time signing secret key
#[derive(Clone, Copy)]
pub struct SecKey {
    /// The address of the WOTS-T keypair within a tree
    pub ots_addr: Addr,
    /// True if this one-time signature key has already been used
    pub used: bool,
}

/// A signature
#[derive(Clone, Copy)]
pub struct Sig {
    chain_ends: [u8; N * L],
    ots_addr: Addr,
    pub_seed: PubSeed,
}

/// A `M` byte message to be signed.
pub type Msg = [u8; M];

impl SecKey {
    /// Create a `SecKey` from an OTS `Addr`.
    pub fn from_ots_addr(ots_addr: &Addr) -> SecKey {
        SecKey {
            ots_addr: *ots_addr,
            used: false,
        }
    }

    /// Signature algorithm
    pub fn sign(&mut self, msg: &Msg, sec_key_seed: &SecKeySeed, pub_seed: &PubSeed) -> Sig {
        assert_eq!(self.used, false); // TODO: replace with Result

        let mut sig = Sig {
            chain_ends: [0; L * N],
            ots_addr: self.ots_addr,
            pub_seed: *pub_seed,
        };

        let b = compute_b(msg);
        for (i, &bi) in b.iter().enumerate() {
            let chain_addr = set_chain_addr(&self.ots_addr, i);
            gen_chain(
                &mut sig.chain_ends[(i * N)..(i * N + N)],
                &prg(&sec_key_seed, &chain_addr),
                bi as usize,
                0,
                &chain_addr,
                pub_seed,
            );
        }
        self.used = true;

        sig
    }
}

/// A public key
#[derive(Clone, Copy)]
pub struct PubKey {
    chain_ends: [u8; N * L],
    ots_addr: Addr,
    pub_seed: PubSeed,
}

impl PubKey {
    /// Generate a public key from a secret key.
    pub fn from_sec_key(sec_key: &SecKey, sec_key_seed: &SecKeySeed, pub_seed: &PubSeed) -> PubKey {
        let mut pub_key = Self {
            chain_ends: [0; N * L],
            ots_addr: sec_key.ots_addr,
            pub_seed: *pub_seed,
        };

        for i in 0..L {
            let chain_addr = set_chain_addr(&sec_key.ots_addr, i);
            let sec_key_i = prg(sec_key_seed, &chain_addr);
            gen_chain(
                &mut pub_key.chain_ends[(i * N)..(i * N + N)],
                &sec_key_i,
                W - 1,
                0,
                &chain_addr,
                pub_seed,
            );
        }

        pub_key
    }

    /// Derive a public key from a message and its signature.
    pub fn from_signed_msg(msg: &Msg, sig: &Sig) -> PubKey {
        let b = compute_b(msg);
        let mut pub_key = Self {
            chain_ends: [0; L * N],
            ots_addr: sig.ots_addr,
            pub_seed: sig.pub_seed,
        };

        for (i, &bi) in b.iter().enumerate() {
            gen_chain(
                &mut pub_key.chain_ends[(i * N)..(i * N + N)],
                &sig.chain_ends[(i * N)..(i * N + N)],
                W - 1 - bi as usize,
                bi as usize,
                &set_chain_addr(&sig.ots_addr, i),
                &sig.pub_seed,
            );
        }

        pub_key
    }

    /// Verify algorithm
    pub fn verify(&self, msg: &Msg, sig: &Sig) -> Choice {
        let pub_key = Self::from_signed_msg(msg, sig);
        pub_key.ct_eq(self)
    }
}

impl ConstantTimeEq for PubKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.chain_ends.ct_eq(&other.chain_ends) & self.ots_addr.ct_eq(&other.ots_addr)
            & self.pub_seed.ct_eq(&other.pub_seed)
    }
}

/// The chaining function.
fn gen_chain(
    out: &mut [u8],
    in_: &[u8],
    iter_ct: usize,
    j: usize, // start_idx
    chain_addr: &Addr,
    pub_seed: &PubSeed,
) {
    out.copy_from_slice(in_);
    let mut xor = [0; N];

    for i in 1..(iter_ct + 1) {
        let key = prg(pub_seed, &set_hash_addr(&chain_addr, 2 * (j + i)));
        let bitmask = prg(pub_seed, &set_hash_addr(&chain_addr, 2 * (j + 1) + 1));
        for i in 0..N {
            xor[i] = out[i] ^ bitmask[i];
        }
        hash(&key, &xor, out);
    }
}

/// Compute B = M || C, the concatenation of the base-`W` representations of the msg and its
/// checksum.
fn compute_b(msg: &Msg) -> [u8; L] {
    let mut b = [0; L];

    // NOTE: hardcoded for W = 16, M = 512, big endian.
    for (i, &byte) in msg.iter().enumerate() {
        b[2 * i] = byte >> 4;
        b[2 * i + 1] = byte & 15;
    }
    let mut csum: usize = b[0..L1].iter().map(|&mi| 15 - mi as usize).sum();
    b[L1] = (csum / (W * W)) as u8;
    csum -= b[L1] as usize * (W * W);
    b[L1 + 1] = (csum / W) as u8;
    b[L1 + 2] = (csum % W) as u8;

    b
}

fn set_hash_addr(addr: &Addr, _i: usize) -> Addr {
    *addr
    // a[15] = (a[15] & 1) | ((v << 1) & 254);
    // a[14] = (a[14] & 254) | ((v >> 7) & 1);
}

fn set_chain_addr(addr: &Addr, _i: usize) -> Addr {
    *addr
    // a[14] = (a[14] & 1) | ((v << 1) & 254);
    // a[13] = (v >> 7) & 255;
    // // a[12] = (a[12] & 254) | ((v >> 15) & 1);
}

/// Pseudorandom function ensemble (keyed blake2b)
fn prg(key: &[u8; N], in_: &[u8; A]) -> [u8; N] {
    let mut out = [0; N];

    unsafe {
        let ret_val = crypto_generichash_blake2b(
            out.as_mut_ptr(),
            N,
            in_.as_ptr(),
            A as u64,
            key.as_ptr(),
            N,
        );
        debug_assert_eq!(ret_val, 0);
    }

    out
}

/// Keyed hash function (keyed blake2b)
fn hash(key: &[u8; N], in_: &[u8; N], out: &mut [u8]) {
    unsafe {
        let ret_val = crypto_generichash_blake2b(
            out.as_mut_ptr(),
            N,
            in_.as_ptr(),
            N as u64,
            key.as_ptr(),
            N,
        );
        debug_assert_eq!(ret_val, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_random_address() -> Addr {
        let mut out = [0; A];
        randombytes_into(&mut out);
        out
    }

    fn gen_random_msg() -> Msg {
        let mut out = [0; M];
        randombytes_into(&mut out);
        out
    }

    fn gen_msg_addr_and_seeds() -> (Msg, Addr, PubSeed, SecKeySeed) {
        let msg = gen_random_msg();
        let ots_addr = gen_random_address();
        let pub_seed = new_pub_seed();
        let sec_key_seed = new_sec_key_seed();
        (msg, ots_addr, pub_seed, sec_key_seed)
    }

    #[test]
    fn sec_key_from_ots_addr() {
        let ots_addr = gen_random_address();

        let sec_key = SecKey::from_ots_addr(&ots_addr);

        assert_eq!(ots_addr, sec_key.ots_addr);
        assert!(!sec_key.used);
    }

    #[test]
    fn pub_key_from_sec_key() {
        let (_, ots_addr, pub_seed, sec_key_seed) = gen_msg_addr_and_seeds();
        let sec_key = SecKey::from_ots_addr(&ots_addr);

        let pub_key = PubKey::from_sec_key(&sec_key, &sec_key_seed, &pub_seed);

        assert_eq!(ots_addr, pub_key.ots_addr);
        // [u8; N] doesn't support `==`, so we use `ct_eq`.
        assert_eq!(pub_seed.ct_eq(&pub_key.pub_seed).unwrap_u8(), 1);
    }

    #[test]
    fn create_and_verify_signature() {
        let (msg, ots_addr, pub_seed, sec_key_seed) = gen_msg_addr_and_seeds();
        let mut sec_key = SecKey::from_ots_addr(&ots_addr);
        let pub_key = PubKey::from_sec_key(&sec_key, &sec_key_seed, &pub_seed);

        let sig = sec_key.sign(&msg, &sec_key_seed, &pub_seed);

        assert_eq!(pub_key.verify(&msg, &sig).unwrap_u8(), 1);
        assert!(sec_key.used);
    }
}
