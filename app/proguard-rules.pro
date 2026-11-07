# Threshold proguard / R8 keep rules
# Per Council iter-1 P0-6: ship with R8 ENABLED + correct keeps.
# family-locator v3.1.1 had a P0 regression where R8 stripped
# fr.acinq.secp256k1 (JNI backend loaded reflectively) and
# com.goteral.lazysodium (JNI). We do NOT repeat this.

# --- Lazysodium (com.goterl.lazysodium) ---
# JNI bridge: native methods are called from Java via JNA; R8 must keep them.
-keep class com.goterl.lazysodium.** { *; }
-keepclassmembers class com.goterl.lazysodium.** {
    native <methods>;
    public *;
}
# JNA itself: loads libs via reflection.
-keep class com.sun.jna.** { *; }
-keepclassmembers class com.sun.jna.** {
    native <methods>;
}
-keep class net.java.dev.jna.** { *; }

# --- secp256k1 (fr.acinq.secp256k1) ---
# JNI backend loaded reflectively by Secp256k1.get().
-keep class fr.acinq.secp256k1.** { *; }
-keepclassmembers class fr.acinq.secp256k1.** {
    native <methods>;
    public *;
}

# --- Kotlinx Serialization ---
# @Serializable classes are looked up by reflection.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class **$$serializer { *; }
-keepclasseswithmembers class * {
    @kotlinx.serialization.Serializable <fields>;
}
-keep,includedescriptorclasses class com.threshold.app.**$$serializer { *; }
-keepclassmembers class com.threshold.app.** {
    *** Companion;
}

# --- OkHttp (uses reflection for platform detection) ---
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# --- Threshold app's own serializable data classes ---
-keep @kotlinx.serialization.Serializable class com.threshold.app.** { *; }
-keepclassmembers class com.threshold.app.** {
    @kotlinx.serialization.SerialName <fields>;
}

# --- Threshold: keep event-kind constants and Defaults object ---
# (wiring-boundary tests read these by reflection to assert wiring correctness)
-keep class com.threshold.app.nostr.EventKinds { *; }
-keep class com.threshold.app.data.Defaults { *; }

# --- AndroidX, Compose, etc. are kept by their own consumer rules ---
