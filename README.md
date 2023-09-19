# web5-sdk-kotlin

This repo contains 4 jvm packages:
* [common](./common) - utilities for encoding, decoding, and hashing
* [crypto](./crypto) - key generation, signing, signature verification, encryption, and decryption
* [dids](./dids) - did generation and resolution
* [credentials](./credentials) - creation and verification of verifiable claims


# Buidling
To build and run test just run:
```bash
./gradlew build && ./gradlew cleanTest test --console=rich
```
