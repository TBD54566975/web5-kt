plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

version = "1.0"

repositories {
  maven {
    url = uri("https://jitpack.io")
  }
  mavenCentral()
  maven {
    url = uri("https://repo.danubetech.com/repository/maven-public")
  }
  maven("https://jitpack.io")
  maven("https://jcenter.bintray.com/")
}

val ktor_version = "2.3.4"

dependencies {
  api("decentralized-identity:did-common-java:1.9.0")
  api("decentralized-identity:uni-resolver-core:0.13.0")

  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.0")
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("com.github.multiformats:java-multibase:1.1.0")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("org.bouncycastle:bcprov-jdk15on:1.70")
  implementation("org.erwinkok.multiformat:multiformat:1.1.0")
  implementation("org.erwinkok.result:result-monad:1.4.0")

  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.8.+")

  implementation("io.ktor:ktor-client-core:$ktor_version")
  implementation("io.ktor:ktor-client-cio:$ktor_version")
  implementation("io.ktor:ktor-client-content-negotiation:$ktor_version")
  implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor_version")
  implementation("io.ktor:ktor-serialization-jackson:$ktor_version")
  implementation("io.ktor:ktor-client-logging:$ktor_version")

  implementation("io.github.erdtman:java-json-canonicalization:1.1")

  testImplementation(kotlin("test"))
  testImplementation("io.ktor:ktor-client-mock:$ktor_version")
}