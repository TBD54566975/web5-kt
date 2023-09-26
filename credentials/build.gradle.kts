import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
  `maven-publish`
}

group = "web5"
version = "0.0.0"

java {
  withJavadocJar()
  withSourcesJar()
}

publishing {
  publications {
    create<MavenPublication>("web5Credentials") {
      from(components["java"])
    }
  }
}

repositories {
  mavenCentral()

  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
}

dependencies {
  testImplementation(kotlin("test"))

  implementation("com.github.richardbergquist:java-multicodec:main-SNAPSHOT")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("decentralized-identity:uni-resolver-core:0.13.0")
  implementation("com.danubetech:verifiable-credentials-java:1.5.0")
  implementation("com.nfeld.jsonpathkt:jsonpathkt:2.0.1")
  implementation("com.googlecode.json-simple:json-simple:1.1.1")
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