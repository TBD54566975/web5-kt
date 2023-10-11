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
}

dependencies {
  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.0")
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("com.github.multiformats:java-multibase:1.1.0")
  implementation("com.google.crypto.tink:tink:1.10.0")
  implementation("decentralized-identity:did-common-java:1.9.0")
  testImplementation(kotlin("test"))
  testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")

}

tasks.test {
  useJUnitPlatform()
}