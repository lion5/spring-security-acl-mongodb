import org.springframework.boot.gradle.tasks.bundling.BootJar

plugins {
    id("org.springframework.boot") version "3.3.1"
    id("io.spring.dependency-management") version "1.1.5"
    id("com.diffplug.spotless") version "6.25.0"
    kotlin("jvm") version "1.9.24"
    kotlin("plugin.spring") version "1.9.24"
    id("maven-publish")
}

group = "org.springframework"
version = "0.0.2-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.security:spring-security-acl")
    implementation("org.springframework.boot:spring-boot-starter-data-mongodb")
    implementation("org.springframework.data:spring-data-mongodb")
    implementation("org.jetbrains.kotlin:kotlin-reflect")

    testImplementation("org.springframework.boot:spring-boot-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:mongodb")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.springframework.security:spring-security-test")

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict")
    }
}

spotless {
    kotlin {
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

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/lion5/spring-security-acl-mongodb")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}

// Disable the bootJar task since this is a library
tasks.named<BootJar>("bootJar") {
    enabled = false
}
