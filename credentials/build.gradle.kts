plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()

  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
  maven("https://repository.jboss.org/nexus/content/repositories/thirdparty-releases/")
}

val ktor_version = "2.3.4"
val jackson_version = "2.13.5"

dependencies {
  api("com.danubetech:verifiable-credentials-java:1.6.0")

  implementation(project(":dids"))
  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jackson_version")
  implementation("com.nfeld.jsonpathkt:jsonpathkt:2.0.1")
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("decentralized-identity:did-common-java:1.9.0")
  implementation("com.networknt:json-schema-validator:1.0.87")

  implementation("io.ktor:ktor-client-core:$ktor_version")
  implementation("io.ktor:ktor-client-okhttp:$ktor_version")
  implementation("io.ktor:ktor-client-content-negotiation:$ktor_version")
  implementation("io.ktor:ktor-serialization-jackson:$ktor_version")
  implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor_version")
  implementation("io.ktor:ktor-client-logging:$ktor_version")

  testImplementation("io.ktor:ktor-client-mock:$ktor_version")

  testImplementation(kotlin("test"))
  testImplementation("com.willowtreeapps.assertk:assertk:0.27.0")
  testImplementation(project(":testing"))
}