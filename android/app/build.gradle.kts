import java.util.Properties

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
val appVersion = "0.28.1"
val (versionMajor, versionMinor, versionPatch) = appVersion.split(".").map(String::toInt)

// The network file of the release, which scripts/release-network.sh writes
// after a deployment. The manifest names its invitation host for the App
// Link (IDN-123). The app reads its epoch at its start (REL-045). A debug
// build needs no such file.
val releaseNetworkFile = file("src/release/assets/umbra-network.properties")
val releaseNetwork = Properties().apply {
    if (releaseNetworkFile.isFile) releaseNetworkFile.inputStream().use { load(it) }
}
val releaseInvitationHost = releaseNetwork.getProperty("invitation_host")?.trim().orEmpty()
val releaseShippedEpoch = releaseNetwork.getProperty("shipped_epoch")?.trim().orEmpty()

// The release signing key. Its place and its password come from the Gradle
// properties of the user (~/.gradle/gradle.properties), never from this
// repository: umbra.release.storeFile, umbra.release.storePassword, and
// umbra.release.keyAlias. With no such properties, the release build is
// unsigned.
val releaseStoreFile = (project.findProperty("umbra.release.storeFile") as String?).orEmpty()
val releaseStorePassword = (project.findProperty("umbra.release.storePassword") as String?).orEmpty()
val releaseKeyAlias = (project.findProperty("umbra.release.keyAlias") as String?) ?: "umbra"
val releaseTest = project.findProperty("umbra.releaseTest") == "true"

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
        // Part 14 §14.6.2: a release ships arm64-v8a alone. The debug type
        // adds the ABI of an emulator.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
        // IDN-123: the App Link of an invitation. A debug build names its
        // invitation host with -Pumbra.invitationHost; the default is the
        // host of the devnet, which no party serves. The release type takes
        // the host of its network file in its place.
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

    signingConfigs {
        if (releaseStoreFile.isNotEmpty()) {
            create("release") {
                storeFile = file(releaseStoreFile)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                // A PKCS12 store has one password for the store and the key.
                keyPassword = releaseStorePassword
            }
        }
    }

    buildTypes {
        // -Pumbra.minify=true shrinks a debug build as R8 shrinks the release,
        // thus a build for the devnet runs the code that ships.
        debug {
            ndk {
                abiFilters += listOf("x86_64")
            }
            if (project.findProperty("umbra.minify") == "true") {
                isMinifyEnabled = true
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro",
                )
            }
        }
        release {
            // IDN-123: the App Link names the host that the app reads from
            // the same file at its start. With no file the name is one that
            // no party can serve, and `checkReleaseNetwork` ends the build.
            manifestPlaceholders["invitationHost"] =
                releaseInvitationHost.ifEmpty { "release-network-absent.invalid" }
            // R8 drops the code that the app never calls, and the resources
            // that nothing names; proguard-rules.pro keeps the Rust bindings.
            // -Pumbra.releaseTest=true gives the release type the ABI of an
            // emulator and the debug signing key. Thus an emulator runs the
            // code and the network that ship, before a release key exists.
            // Such a build is no release: do not publish it.
            if (releaseTest) {
                ndk {
                    abiFilters += listOf("x86_64")
                }
                signingConfig = signingConfigs.getByName("debug")
            } else if (releaseStoreFile.isNotEmpty()) {
                signingConfig = signingConfigs.getByName("release")
            }
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

// With no network file or with the host of the devnet, the App Link of a
// release would name a host that no party serves (IDN-123). With no epoch, a
// first launch would take each old manifest that a carrier gives (REL-045,
// REL-046).
val checkReleaseNetwork = tasks.register("checkReleaseNetwork") {
    val path = releaseNetworkFile.absolutePath
    val isPresent = releaseNetworkFile.isFile
    val host = releaseInvitationHost
    val epoch = releaseShippedEpoch
    inputs.property("isPresent", isPresent)
    inputs.property("host", host)
    inputs.property("epoch", epoch)
    doLast {
        val problems = buildList {
            if (!isPresent) {
                add("$path is absent: run scripts/release-network.sh after the deployment")
            } else {
                val isHost = Regex("""[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+""").matches(host)
                if (!isHost) add("invitation_host of $path is no host name: \"$host\"")
                if (host == "invite.umbra.test" || host.endsWith(".test") || host.endsWith(".invalid")) {
                    add("invitation_host of $path is the host of the devnet: \"$host\"")
                }
                if ((epoch.toULongOrNull() ?: 0uL) == 0uL) {
                    add("shipped_epoch of $path is absent or zero: \"$epoch\" (REL-045)")
                }
            }
        }
        if (problems.isNotEmpty()) {
            throw GradleException("The release has no network:\n  " + problems.joinToString("\n  "))
        }
    }
}
tasks.matching { it.name == "preReleaseBuild" }.configureEach { dependsOn(checkReleaseNetwork) }

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
