

plugins {

    application

    id("com.github.johnrengelman.shadow") version "8.1.1"
}

repositories {

    mavenCentral()
}

dependencies {

    testImplementation(libs.junit.jupiter)

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    implementation(libs.guava)

    implementation("com.github.gumtreediff:core:3.0.0")
    implementation("com.github.gumtreediff:gen.srcml:3.0.0")
    implementation("com.github.gumtreediff:client.diff:3.0.0")

    implementation("com.google.code.gson:gson:2.10.1")

    implementation("org.apache.commons:commons-text:1.10.0")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {

    mainClass = "org.example.App"
}

tasks.named<Test>("test") {

    useJUnitPlatform()
}

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveClassifier.set("")
}
