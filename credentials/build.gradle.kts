import org.gradle.api.tasks.testing.logging.TestExceptionFormat

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
  implementation(project(mapOf("path" to ":dids")))
  implementation(project(mapOf("path" to ":dids")))
  testImplementation(kotlin("test"))

  implementation("com.github.richardbergquist:java-multicodec:main-SNAPSHOT")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("decentralized-identity:uni-resolver-core:0.13.0")
  implementation("com.danubetech:verifiable-credentials-java:1.5.0")
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
