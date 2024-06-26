plugins {
	id("org.springframework.boot") version "3.3.1"
	id("io.spring.dependency-management") version "1.1.5"
	id("com.diffplug.spotless") version "6.25.0"
	kotlin("jvm") version "1.9.24"
	kotlin("plugin.spring") version "1.9.24"
}

group = "org.springframework"
version = "0.0.1-SNAPSHOT"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

repositories {
	mavenCentral()
}

dependencies {
//	implementation("org.springframework.boot:spring-boot-starter-data-mongodb")
//	implementation("org.springframework.boot:spring-boot-starter-security")
	implementation("org.springframework.security:spring-security-acl")
    implementation("org.springframework.boot:spring-boot-starter-data-mongodb")
	implementation("org.springframework.data:spring-data-mongodb")
	implementation("org.jetbrains.kotlin:kotlin-reflect")
	testImplementation("org.springframework.boot:spring-boot-test")
	testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
	testImplementation("org.springframework.security:spring-security-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // Embedded MongoDB used for integration testing
    testImplementation("de.flapdoodle.embed:de.flapdoodle.embed.mongo:2.0.3")

}

kotlin {
	compilerOptions {
		freeCompilerArgs.addAll("-Xjsr305=strict")
	}
}

spotless {
	kotlin {
		// by default the target is every '.kt' and '.kts` file in the java sourcesets
		ktfmt("0.50").kotlinlangStyle()
		ktlint("1.3.0").setEditorConfigPath("$projectDir/.editorconfig")
	}
	kotlinGradle {
		ktlint("1.3.0")
	}
}

tasks.withType<Test> {
	useJUnitPlatform()
}
