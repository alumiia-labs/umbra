plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "org.umbra.app"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "org.umbra.app"
        // The NDK build of scripts/android.sh links against this level.
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            // The UniFFI bindings, which scripts/android.sh writes.
            kotlin.srcDir("src/main/kotlin-generated")
        }
    }
}

// The debug build trusts the test authority of the repository and dials the
// network of scripts/devnet.sh. The release build holds neither.
abstract class CopyTestAuthority : DefaultTask() {
    @get:InputFile
    abstract val authority: RegularFileProperty

    @get:OutputDirectory
    abstract val output: DirectoryProperty

    @TaskAction
    fun copy() {
        val target = output.get().file("devnet-ca.pem").asFile
        authority.get().asFile.copyTo(target, overwrite = true)
    }
}

val copyTestAuthority = tasks.register<CopyTestAuthority>("copyTestAuthority") {
    authority.set(rootProject.layout.projectDirectory.file("../tests/fixtures/tls/ca.pem"))
}

androidComponents {
    onVariants(selector().withBuildType("debug")) { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(
            copyTestAuthority,
            CopyTestAuthority::output,
        )
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    // The QR code of an invitation link and of a safety number. The core of
    // ZXing writes and reads a code, and CameraX gives the frames.
    implementation(libs.zxing.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    // The generated bindings call the shared library through JNA.
    implementation("${libs.jna.get()}@aar")
}
