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
  api("com.danubetech:verifiable-credentials-java:1.5.0")

  implementation(project(":dids"))
  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.0")
  implementation("com.nfeld.jsonpathkt:jsonpathkt:2.0.1")
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("decentralized-identity:did-common-java:1.9.0")
  implementation("com.networknt:json-schema-validator:1.0.87")

  testImplementation(kotlin("test"))
  testImplementation("com.willowtreeapps.assertk:assertk:0.27.0")
}