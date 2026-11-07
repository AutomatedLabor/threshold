plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

import java.util.Properties

android {
    namespace = "com.threshold.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.threshold.app"
        // Build-contract §2: min SDK 26 (StrongBox / Android KeyStore hardware-backed
        // keys widely available from API 26+). Target SDK 34.
        minSdk = 26
        targetSdk = 34
        // v1.0.0 initial release (post Council iter-1, all P0s resolved).
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
        ndk {
            // Real-device ABIs only (matches family-locator v2.2.0 R-P2-1).
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // Release signing config. Env vars (CI) or local keystore/keystore.properties (dev).
    signingConfigs {
        create("release") {
            val envKeystore = System.getenv("THRESHOLD_KEYSTORE_FILE")
            val localKeystore = rootProject.file("keystore/threshold-release.keystore")
            storeFile = when {
                envKeystore != null && file(envKeystore).exists() -> file(envKeystore)
                localKeystore.exists() -> localKeystore
                else -> null
            }
            val ksProps = Properties().apply {
                val f = rootProject.file("keystore/keystore.properties")
                if (f.exists()) f.inputStream().use { load(it) }
            }
            storePassword = System.getenv("THRESHOLD_KEYSTORE_PASSWORD")
                ?: ksProps.getProperty("storePassword") ?: ""
            keyAlias = System.getenv("THRESHOLD_KEY_ALIAS")
                ?: ksProps.getProperty("keyAlias") ?: "threshold-release"
            keyPassword = System.getenv("THRESHOLD_KEY_PASSWORD")
                ?: ksProps.getProperty("keyPassword") ?: ""
            // Per build-contract §10 right-first checklist:
            //   - v1 disabled (minSdk 26 → all supported devices understand v2)
            //   - v2 enabled (Android 7+)
            //   - v3 enabled (Android 9+, key rotation / lineage support)
            enableV1Signing = false
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    val releaseKeystorePresent = (System.getenv("THRESHOLD_KEYSTORE_FILE")?.let { file(it).exists() } == true) ||
        rootProject.file("keystore/threshold-release.keystore").exists() ||
        rootProject.file("keystore/keystore.properties").exists()

    buildTypes {
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            // Council iter-1 P0-6: ship with R8 ENABLED + correct keeps.
            // (family-locator v3.1.1 had a P0 regression with R8 disabled — we
            // do NOT repeat that. Keeps for lazysodium + secp256k1 JNI are in
            // proguard-rules.pro. CI runs a wiring-boundary test on the R8-processed
            // APK that asserts crypto round-trip works post-R8.)
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (releaseKeystorePresent) {
                signingConfig = signingConfigs.getByName("release")
            }
            isDebuggable = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        // Kotlin 2.0 ships its own Compose compiler plugin via
        // org.jetbrains.kotlin.plugin.compose (built-in to kotlin-android).
        kotlinCompilerExtensionVersion = "1.5.14"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/META-INF/io.netty.versions.properties"
        }
    }
    testOptions {
        unitTests {
            isReturnDefaultValues = true
            isIncludeAndroidResources = false
        }
    }
}

dependencies {
    // Core
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-service:2.8.2")
    implementation("androidx.activity:activity-compose:1.9.0")

    // Compose
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.7.7")

    // WorkManager (battery-friendly background heartbeat)
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // Crypto: libsodium (crypto_box_seal, sodium_memzero)
    implementation("com.goterl:lazysodium-android:5.1.0@aar")
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    // secp256k1 (BIP340 Schnorr for nostr event signing)
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jvm:0.16.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.16.0")

    // Secure preferences
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // OkHttp WebSocket (relays)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Biometric
    implementation("androidx.biometric:biometric:1.1.0")

    // Unit tests
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("org.json:json:20240303")

    // Android tests (defined for completeness; not run in this sandbox)
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
