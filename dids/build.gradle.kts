plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
  maven("https://repo.danubetech.com/repository/maven-public")
  maven("https://jitpack.io")
  maven("https://jcenter.bintray.com/")
  maven("https://repository.jboss.org/nexus/content/repositories/thirdparty-releases/")
}

val ktor_version = "2.3.4"
val jackson_version = "2.14.2"

dependencies {
  api("decentralized-identity:did-common-java:1.9.0")

  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jackson_version")
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("com.github.multiformats:java-multibase:1.1.0")
  implementation("io.github.oshai:kotlin-logging-jvm:6.0.2")

  implementation("io.ktor:ktor-client-core:$ktor_version")
  implementation("io.ktor:ktor-client-okhttp:$ktor_version")
  implementation("io.ktor:ktor-client-content-negotiation:$ktor_version")
  implementation("io.ktor:ktor-serialization-jackson:$ktor_version")

  implementation("com.squareup.okhttp3:okhttp-dnsoverhttps:4.12.0")

  implementation("io.github.erdtman:java-json-canonicalization:1.1")

  testImplementation(kotlin("test"))
  testImplementation("io.ktor:ktor-client-mock:$ktor_version")
  testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
  testImplementation("commons-codec:commons-codec:1.16.0")

  implementation("dnsjava:dnsjava:3.5.2")
  testImplementation(project(mapOf("path" to ":testing")))
}