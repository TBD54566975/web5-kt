plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

version = "1.0"

repositories {
  mavenCentral()
}

dependencies {
  implementation(project(":common"))
}

tasks.test {
  useJUnitPlatform()
}