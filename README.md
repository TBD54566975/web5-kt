# web5-sdk-kotlin

[![License](https://img.shields.io/github/license/TBD54566975/web5-kt)](https://github.com/TBD54566975/web5-kt/blob/main/LICENSE)
[![SDK Kotlin CI](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml/badge.svg)](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/codecov/c/gh/tbd54566975/web5-kt/main?logo=codecov&logoColor=FFFFFF&style=flat-square&token=YI87CKF1LI)](https://codecov.io/github/TBD54566975/web5-kt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/TBD54566975/web5-kt/badge)](https://securityscorecards.dev/viewer/?uri=github.com/TBD54566975/web5-kt)

This repo contains 5 packages:

* [common](./common) - utilities for encoding, decoding, and hashing
* [crypto](./crypto) - key generation, signing, signature verification, encryption, and decryption
* [dids](./dids) - did generation and resolution
* [credentials](./credentials) - creation and verification of verifiable claims
* [jose](./jose) - JSON Object Signing with JWS and JWT support for encoding/decoding, signing, and serialization 

# Quickstart

You can add this library to your project using Gradle or Maven. To do so, pull the package from Maven Central.

## Maven Central

When pulling from Maven Central, you can pull the entire library or just a single module. Examples of both are shown
below. Please note that you need to add the repositories shown below to your `build.gradle.kts` file. This is because
the libraries that we depend on are hosted in separate places.

```kt
repositories {
  mavenCentral()
  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
}

dependencies {
  // If you want to pull the entire library
  implementation("xyz.block:web5:0.10.0")

  // If you want to pull a single module
  implementation("xyz.block:web5-common:0.10.0")
  implementation("xyz.block:web5-credentials:0.10.0")
  implementation("xyz.block:web5-crypto:0.10.0")
  implementation("xyz.block:web5-dids:0.10.0")
}
```

> [!IMPORTANT]
> Additional repositories, like `https://repo.danubetech.com/repository/maven-public/`, are required for resolving
transitive dependencies.

# Examples

Examples are hosted in the public documentation for each module, which is hosted
in [GitHub Pages](https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/credentials/index.html).

# Development

## Prerequisites

### Cloning

This repository uses git submodules. To clone this repo with submodules

```sh
git clone --recurse-submodules git@github.com:TBD54566975/web5-kt.git
```

Or to add submodules after cloning

```sh
git submodule update --init
```

We recommend this config which will only checkout the files relevant to web5-kt

```sh
git -C web5-spec sparse-checkout set test-vectors
```

### Hermit

This project uses hermit to manage tooling like gradle and java verions.
See [this page](https://cashapp.github.io/hermit/usage/get-started/) to set up Hermit on your machine - make sure to
download the open source build and activate it for the project.

## Testing with local builds

If you want to build an artifact locally, you can do so by running the following command - either at the top level or in
any of the subprojects:

```sh
gradle publishToMavenLocal -PskipSigning=true -Pversion={your-local-version-name}
```

## Dependency Management

As Web5 is a platform intended to run in a single `ClassLoader`,
versions and dependencies must be aligned among the subprojects
(sometimes called modules) of this project. To address, we declare
versions in `gradle/libs.versions.toml` and import references defined
there in the subproject `build.gradle.kts` files. More docs on this
approach using Gradle Version Catalogs is at the top of `gradle/libs.versions.toml`.

We have a secondary mechanism to force dependency upgrades of transitive
deps in the case we encounter security vulnerabilities we do not directly
depend upon. That config is located in the `resolutionStrategy` section of
`./build.gradle.kts`. Notes for applying fixes for security vulnerabilities
are documented there.

## Build

To build and run test just run:

```bash
gradle build --console=rich
```

## Release Guidelines

### Pre-releases

In Kotlin we use the SNAPSHOT convention to build and publish a pre-release package that can be consumed for preview/tests purposes.

To kick that off:

1. Open the [Publish workflow](https://github.com/TBD54566975/web5-kt/actions/workflows/publish.yml), press the **Run workflow button** selecting the branch you want to generate the snapshot from.

2. In the version field, insert the current version, a short meaningful identifier and the `-SNAPSHOT` prefix, ie:

   - 0.11.0.pr123-SNAPSHOT
   - 0.11.0.shortsha-SNAPSHOT
   - 0.11.0.fixsomething-SNAPSHOT

3. Run workflow!

**DON'T FORGET THE `-SNAPSHOT` SUFFIX**, otherwise it will generate publish a new official release to maven registry.

### Releasing New Versions

To release a new version, just execute the following steps:

1. Open the [Publish workflow](https://github.com/TBD54566975/tbdex-kt/actions/workflows/publish.yaml), press the **Run workflow button** and leave the main branch selected (unless its a rare case where you don't want to build the main branch for the release).

2. In the version field, insert the new version to be released, ie: 0.12.3-beta

3. Run workflow! The package will be built and **published to maven central**, **docs will be published** (see below) and **the GitHub release will be automatically generated**!

## Publishing Docs

API reference documentation is automatically updated are available at [https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/](https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/) following each automatically generated release.

## Working with the `web5-spec` submodule

### Pulling

You may need to update the `web5-spec` submodule after pulling.

```sh
git pull
git submodule update
```

### Pushing

If you have made changes to the `web5-spec` submodule, you should push your changes to the `web5-spec` remote as well as
pushing changes to `web5-kt`.

```sh
cd web5-spec
git push
cd ..
git push
```

# Other Docs

* [Guidelines](./CONVENTIONS.md)
* [Code of Conduct](./CODE_OF_CONDUCT.md)
* [Governance](./GOVERNANCE.md)
