plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

version = "1.0"

repositories {
  mavenCentral()
  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
}

dependencies {
  implementation(project(":common"))
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("decentralized-identity:did-common-java:1.9.0")
  testImplementation(kotlin("test"))
  implementation("com.github.richardbergquist:java-multicodec:main-SNAPSHOT")
  implementation("com.github.multiformats:java-multibase:1.1.1")
}

tasks.test {
  useJUnitPlatform()
}