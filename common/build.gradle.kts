plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
}

dependencies {
  testImplementation(kotlin("test"))
}
