import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    kotlin("jvm") version "2.0.21"
}

group   = "io.automaguard"
version = "0.1.0-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
    maven("https://repo.spring.io/milestone")
}

dependencies {
    // Core: JSON deserialisation of PolicyResult
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")

    // Kotlin stdlib (optional — only needed for Kotlin callers)
    compileOnly(kotlin("stdlib"))

    // Spring AI (optional)
    compileOnly("org.springframework.ai:spring-ai-core:1.0.0")

    // LangChain4j (optional)
    compileOnly("dev.langchain4j:langchain4j:0.36.0")

    // Tests
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testImplementation("org.assertj:assertj-core:3.26.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    sourceSets["main"].kotlin.srcDir("src/main/kotlin")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "17"
}

// ── Build the Rust JNI library before compiling Java ─────────────────────────

val buildRustJni by tasks.registering(Exec::class) {
    description = "Compile the aegis-jni Rust crate"
    workingDir  = file("rust")
    commandLine("cargo", "build", "--release")
}

tasks.compileJava { dependsOn(buildRustJni) }

// ── Copy native library into the JAR resources ────────────────────────────────

val copyNativeLib by tasks.registering(Copy::class) {
    description = "Bundle the platform native library into the JAR"
    dependsOn(buildRustJni)

    // Detect current platform
    val os   = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()

    val osDir   = when {
        os.contains("linux")   -> "linux"
        os.contains("mac")     -> "macos"
        os.contains("windows") -> "windows"
        else                   -> "unknown"
    }
    val archDir = when {
        arch == "amd64" || arch == "x86_64"         -> "x86_64"
        arch == "aarch64" || arch == "arm64"        -> "aarch64"
        else                                        -> "unknown"
    }

    from("rust/target/release") {
        include("libaegis_jni.so", "libaegis_jni.dylib", "aegis_jni.dll")
    }
    into(layout.buildDirectory.dir("resources/main/native/$osDir/$archDir"))
}

tasks.processResources { dependsOn(copyNativeLib) }

// ── Tests — tell the JVM where to find the native library ────────────────────

tasks.test {
    useJUnitPlatform()
    jvmArgs("-Djava.library.path=${file("rust/target/release").absolutePath}")
}
