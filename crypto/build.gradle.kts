plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
}

val bouncy_castle_version = "1.77"
val jackson_version = "2.14.2"

dependencies {
  api("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("org.bouncycastle:bcprov-jdk15to18:$bouncy_castle_version")
  implementation("org.bouncycastle:bcpkix-jdk15to18:$bouncy_castle_version")
  implementation(project(":common"))

  api("com.amazonaws:aws-java-sdk-kms:1.12.538")

  testImplementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jackson_version")
  testImplementation(kotlin("test"))
  testImplementation(project(":testing"))
}