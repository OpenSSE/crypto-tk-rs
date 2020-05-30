# OpenSSE's Rust Cryptographic Toolkit

Searchable encryption protocols, like other cryptographic protocols, rely on high level cryptographic features such as pseudo-random functions, hash functions, or encryption schemes. This toolkit provides interfaces and implementations of these features in Rust.

## Why a new crypto library

A lot of great crypto libraries exist out there (_e.g._ [libsodium](https://github.com/jedisct1/libsodium)). Unfortunately, they do not offer the level of abstraction needed to implement searchable encryption schemes easily. Indeed, cryptographic objects such as pseudo-random functions, trapdoor permutations, pseudo-random generators, _etc_, are building blocks of such constructions, and OpenSSL, [Rust-Crypto](https://github.com/DaGenix/rust-crypto/), libsodium bindings in Rust do not offer interfaces to such objects.

This library provides these APIs so that any implementer of a cryptographic algorithm/protocol has a consistent and secure high-level crypto interface to these primitives and does not have to care about their implementation.

It is a Rust counterpart of [OpenSSE's crypto-tk](https://github.com/OpenSSE/crypto-tk) library.

## Disclaimer

This is code for a **research project**. It **should not be used in production**: the code lacks good Rust security practice, and it has never been externally reviewed.

## Contributors

Unless otherwise stated, this code has been written by [Raphael Bost](https://raphael.bost.fyi/).

## Licensing

This code is licensed under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl.html).

![AGPL](https://www.gnu.org/graphics/agplv3-88x31.png)

