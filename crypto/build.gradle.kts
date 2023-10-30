plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
}

dependencies {
  api("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("org.bouncycastle:bcprov-jdk15on:1.70")
  implementation("org.bouncycastle:bcpkix-jdk15on:1.70")
  implementation(project(":common"))

  api("com.amazonaws:aws-java-sdk-kms:1.12.538")

  testImplementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.0")
  testImplementation(kotlin("test"))
}