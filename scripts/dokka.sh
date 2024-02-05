#!/bin/bash

# setup dokka cli
if [ ! -d "./target/dokka-cli" ]; then
  mkdir -p ./target/dokka-cli
  wget -O ./target/dokka-cli/dokka-cli.jar https://repo1.maven.org/maven2/org/jetbrains/dokka/dokka-cli/1.9.20/dokka-cli-1.9.20.jar
  wget -O ./target/dokka-cli/dokka-base.jar https://repo1.maven.org/maven2/org/jetbrains/dokka/dokka-base/1.9.20/dokka-base-1.9.20.jar
  wget -O ./target/dokka-cli/analysis-kotlin-descriptors.jar https://repo1.maven.org/maven2/org/jetbrains/dokka/analysis-kotlin-descriptors/1.9.20/analysis-kotlin-descriptors-1.9.20.jar
  wget -O ./target/dokka-cli/kotlinx-html-jvm.jar https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-html-jvm/0.8.0/kotlinx-html-jvm-0.8.0.jar
  wget -O ./target/dokka-cli/freemarker.jar https://repo1.maven.org/maven2/org/freemarker/freemarker/2.3.31/freemarker-2.3.31.jar
fi

java -jar ./target/dokka-cli/dokka-cli.jar ./scripts/dokka-configuration.json
