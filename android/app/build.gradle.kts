plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// The Firebase project of a deployment gives `google-services.json`, which the
// repository does not hold. A build without it has no Firebase app, and the
// app runs with no push.
if (file("google-services.json").exists()) {
    apply(plugin = "com.google.gms.google-services")
}

// The semantic version of the app, the same as the Rust workspace and the
// specification. The code grows with each one: major, minor, then patch, three
// digits each.
val appVersion = "0.10.0"
val (versionMajor, versionMinor, versionPatch) = appVersion.split(".").map(String::toInt)

android {
    namespace = "com.alumiialabs.umbra"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        // The store identity, which never changes once published.
        applicationId = "com.alumiialabs.umbra"
        // The NDK build of scripts/android.sh links against this level.
        minSdk = 29
        targetSdk = 36
        versionCode = versionMajor * 1_000_000 + versionMinor * 1_000 + versionPatch
        versionName = appVersion
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        // IDN-123: the App Link of an invitation. A deployment names its
        // invitation host with -Pumbra.invitationHost; the default is the
        // host of the devnet, which no party serves.
        manifestPlaceholders["invitationHost"] =
            (project.findProperty("umbra.invitationHost") as String?) ?: "invite.umbra.test"
        // The IPv4 address of the machine of scripts/devnet.sh, which the
        // debug build dials. The default serves an emulator. A phone on the
        // local network takes -Pumbra.devnetHost=<address of that machine>.
        val devnetHost = (project.findProperty("umbra.devnetHost") as String?) ?: "10.0.2.2"
        require(devnetHost.split('.').let { parts -> parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 } }) {
            "umbra.devnetHost takes an IPv4 address"
        }
        buildConfigField("String", "DEVNET_HOST", "\"$devnetHost\"")
    }

    buildTypes {
        // -Pumbra.minify=true shrinks a debug build as R8 shrinks the release,
        // thus a build for the devnet runs the code that ships.
        debug {
            if (project.findProperty("umbra.minify") == "true") {
                isMinifyEnabled = true
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro",
                )
            }
        }
        release {
            // R8 drops the code that the app never calls, and the resources
            // that nothing names; proguard-rules.pro keeps the Rust bindings.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
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

    /** The key set of the seven test authorities of the relay directory. */
    @get:InputFile
    abstract val keyset: RegularFileProperty

    /** The gateway key of the NDR of the devnet (Part 8 `NTF-127`). */
    @get:InputFile
    abstract val ndrKey: RegularFileProperty

    /** The pins of the directory of the devnet (Part 9 `DIS-163`). */
    @get:InputFile
    abstract val directoryPins: RegularFileProperty

    @get:OutputDirectory
    abstract val output: DirectoryProperty

    @TaskAction
    fun copy() {
        val target = output.get().file("devnet-ca.pem").asFile
        authority.get().asFile.copyTo(target, overwrite = true)
        val keys = output.get().file("devnet-keyset.bin").asFile
        keyset.get().asFile.copyTo(keys, overwrite = true)
        val ndr = output.get().file("devnet-ndr-key.bin").asFile
        ndrKey.get().asFile.copyTo(ndr, overwrite = true)
        val directory = output.get().file("devnet-directory-pins.bin").asFile
        directoryPins.get().asFile.copyTo(directory, overwrite = true)
    }
}

val copyTestAuthority = tasks.register<CopyTestAuthority>("copyTestAuthority") {
    authority.set(rootProject.layout.projectDirectory.file("../tests/fixtures/tls/ca.pem"))
    keyset.set(rootProject.layout.projectDirectory.file("../tests/fixtures/devnet/keyset.bin"))
    ndrKey.set(rootProject.layout.projectDirectory.file("../tests/fixtures/devnet/ndr-key-config.bin"))
    directoryPins.set(rootProject.layout.projectDirectory.file("../tests/fixtures/devnet/directory-pins.bin"))
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
    // Play services brings Fragment 1.0, whose activity drops the results
    // of the permission request; this takes the version that delivers them.
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    // The QR code of an invitation link and of a safety number. The core of
    // ZXing writes and reads a code, and CameraX gives the frames.
    implementation(libs.zxing.core)
    // The FCM carrier of Part 8 §8.4.1.
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.messaging)
    // The poll of a build with no Firebase app.
    implementation(libs.androidx.work)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    // The generated bindings call the shared library through JNA.
    implementation("${libs.jna.get()}@aar")
}
