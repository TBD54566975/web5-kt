plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()

  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
}

val ktor_version = "2.3.4"

dependencies {
  api("com.danubetech:verifiable-credentials-java:1.5.0")

  implementation(project(":dids"))
  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.0")
  implementation("com.nfeld.jsonpathkt:jsonpathkt:2.0.1")
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("decentralized-identity:did-common-java:1.9.0")

  implementation("io.ktor:ktor-client-core:$ktor_version")
  implementation("io.ktor:ktor-client-cio:$ktor_version")
  implementation("io.ktor:ktor-client-content-negotiation:$ktor_version")
  implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor_version")
  implementation("io.ktor:ktor-client-logging:$ktor_version")

  testImplementation("io.ktor:ktor-client-mock:$ktor_version")

  testImplementation(kotlin("test"))
}