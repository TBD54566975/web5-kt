import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()

  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
}

dependencies {
  testImplementation(kotlin("test"))

  api("com.danubetech:verifiable-credentials-java:1.5.0")
  api("com.nimbusds:nimbus-jose-jwt:9.34")
  api("decentralized-identity:did-common-java:1.9.0")
  api("decentralized-identity:uni-resolver-core:0.13.0")

  implementation(project(":dids"))
  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation("com.github.richardbergquist:java-multicodec:main-SNAPSHOT")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.0")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("com.nfeld.jsonpathkt:jsonpathkt:2.0.1")
}

tasks.test {
  useJUnitPlatform()
  testLogging {
    events("passed", "skipped", "failed", "standardOut", "standardError")
    exceptionFormat = TestExceptionFormat.FULL
    showExceptions = true
    showCauses = true
    showStackTraces = true
  }
}