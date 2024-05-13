# [NCC Group]: FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 203] (Initial Public Draft) Module-Lattice-Based Key-Encapsulation Mechanism Standard written in pure Rust for
server, desktop, browser and embedded applications. The source repository includes examples demonstrating benchmarking, 
an embedded target, constant-time statistical measurements, fuzzing, WASM execution, C FFI and Python bindings.

This crate implements the FIPS 203 **draft** standard in pure Rust with minimal and mainstream dependencies, **and 
without any unsafe code**. All three security parameter sets are fully supported and tested. The implementation operates
in constant-time (outside of rho, which is part of the encapsulation key sent across the trust boundary in the clear), 
does not require the standard library, e.g. `#[no_std]`, has no heap allocations, e.g. no `alloc` needed, and optionally 
exposes the `RNG` so it is suitable for the full range of applications down to the bare-metal. The API is stabilized 
and the code is heavily biased towards safety and correctness; further performance optimizations will be implemented 
as the standard matures. This crate will quickly follow any changes to FIPS 203 as they become available.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf> for a full description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
// Use the desired target parameter set.
use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024. 
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

// Alice runs `try_keygen()` and then serializes the encaps key `ek` for Bob (to bytes).
let (alice_ek, alice_dk) = ml_kem_512::KG::try_keygen().unwrap();
let alice_ek_bytes = alice_ek.into_bytes();

// Alice sends the encaps key `ek_bytes` to Bob.
let bob_ek_bytes = alice_ek_bytes;

// Bob deserializes the encaps `ek_bytes` and then runs `encaps() to get the shared 
// secret `ssk` and ciphertext `ct`. He serializes the ciphertext `ct` for Alice (to bytes).
let bob_ek = ml_kem_512::EncapsKey::try_from_bytes(bob_ek_bytes).unwrap();
let (bob_ssk_bytes, bob_ct) = bob_ek.try_encaps().unwrap();
let bob_ct_bytes = bob_ct.into_bytes();

// Bob sends the ciphertext `ct_bytes` to Alice
let alice_ct_bytes = bob_ct_bytes;

// Alice deserializes the ciphertext `ct` and runs `decaps()` with her decaps key
let alice_ct = ml_kem_512::CipherText::try_from_bytes(alice_ct_bytes).unwrap();
let alice_ssk_bytes = alice_dk.try_decaps(&alice_ct).unwrap();

// Alice and Bob will now have the same secret key
assert_eq!(bob_ssk_bytes, alice_ssk_bytes);
~~~

The Rust [Documentation][docs-link] lives under each **Module** corresponding to the desired
[security parameter](#modules) below.

## Notes

* This crate is fully functional and corresponds to the first initial public draft of FIPS 203.
* Constant-time operation targets the source-code level only on MSRV, with confirmation via 
  manual review/inspection, the embedded target, and the `dudect` dynamic tests.
* Note that FIPS 203 places specific requirements on randomness per section 3.3, hence the exposed `RNG`.
* Requires Rust **1.70** or higher. The minimum supported Rust version (MSRV) may be changed in the future,
  but it will be done with a minor version bump (when the major version is larger than 0).
* All on-by-default features of this library are covered by SemVer.
* The FIPS 203 draft standard and this software is experimental -- USE AT YOUR OWN RISK!

## License

Contents are licensed under either the [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/fips203

[crate-link]: https://crates.io/crates/fips203

[docs-image]: https://docs.rs/fips203/badge.svg

[docs-link]: https://docs.rs/fips203/

[build-image]: https://github.com/nccgroup/fips203/workflows/test/badge.svg

[build-link]: https://github.com/nccgroup/fips203/actions?query=workflow%3Atest
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg

[rustc-image]: https://img.shields.io/badge/rustc-1.70+-blue.svg

[//]: # (general links)

[NCC Group]: https://github.com/nccgroup/
[FIPS 203]: https://csrc.nist.gov/pubs/fips/203/ipd
