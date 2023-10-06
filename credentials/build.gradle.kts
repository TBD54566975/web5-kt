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

val ktor_version = "2.3.4"

dependencies {
  testImplementation(kotlin("test"))

  api("com.danubetech:verifiable-credentials-java:1.5.0")
  api("com.nimbusds:nimbus-jose-jwt:9.34")
  api("decentralized-identity:did-common-java:1.9.0")
  api("decentralized-identity:uni-resolver-core:0.13.0")

  implementation("com.github.richardbergquist:java-multicodec:main-SNAPSHOT")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("com.nfeld.jsonpathkt:jsonpathkt:2.0.1")

  implementation("io.ktor:ktor-client-core:$ktor_version")
  implementation("io.ktor:ktor-client-cio:$ktor_version")
  implementation("io.ktor:ktor-client-content-negotiation:$ktor_version")
  implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor_version")
  implementation("io.ktor:ktor-client-logging:$ktor_version")

  testImplementation("io.ktor:ktor-client-mock:$ktor_version")
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