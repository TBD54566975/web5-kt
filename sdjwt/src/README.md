# SD-JWT support in Kotlin

`sdjwt` is a library that implements the IETF draft
for [Selective Disclosure for JWTs](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html).
This library facilitates creating SD-JWT structures for issuance and presentation with arbitrary payloads, and
performing
verification from the holder or from the verifier's perspective.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API REFERENCE](#api-reference)

## Installation

Add the following to your `gradle.build.kts` file:

```kotlin
repositories {
  maven(url = "https://jitpack.io")
}

dependencies {
  implementation("com.github.TBD54566975.web5-kt:sd-jwt:main-SNAPSHOT")
}
```

## Quick Start

See the test named `whole flow from issuer to holder to verifier`
from [this file](./test/kotlin/web5/security/SdJwtTest.kt).
You can run it by cloning this repo and running gradle as shown below:

```shell
go clone github.com/TBD54566975/web5-kt.git
cd web5-kt/
./gradlew sdjwt:test
```

## API Reference

See our [oficial kotlin docs](https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/sdjwt/index.html).
 
