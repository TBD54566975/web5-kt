import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm

plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
  id("com.vanniktech.maven.publish.base")
}

version = "0.1.0"

repositories {
  mavenCentral()
}

dependencies {
  testImplementation(kotlin("test"))
  testImplementation("org.junit.jupiter:junit-jupiter:5.8.1")
}

tasks.test {
  useJUnitPlatform()
}

java {
  withJavadocJar()
  withSourcesJar()
}


mavenPublishing {
  configure(KotlinJvm(
    sourcesJar = true,
    javadocJar = JavadocJar.Javadoc()
  ))
}