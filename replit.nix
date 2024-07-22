{ pkgs }: {
	deps = [
		pkgs.jdk11
		pkgs.kotlin
		pkgs.gradle
		pkgs.maven
		pkgs.kotlin-language-server
	];
}