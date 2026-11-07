pluginManagement {
    repositories {
        // Aliyun mirror FIRST to avoid Maven Central 429 rate-limits (per family-locator LEARNINGS).
        maven { url = uri("https://maven.aliyun.com/repository/gradle-plugin") }
        maven { url = uri("https://maven.aliyun.com/repository/public") }
        maven { url = uri("https://maven.aliyun.com/repository/google") }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    resolutionStrategy {
        eachPlugin {
            val id = requested.id.id
            val ver = requested.version
            if (id == "com.android.application" && ver != null) {
                useModule("com.android.tools.build:gradle:${ver}")
            } else if (id == "org.jetbrains.kotlin.plugin.compose" && ver != null) {
                useModule("org.jetbrains.kotlin:compose-compiler-gradle-plugin:${ver}")
            } else if (id == "org.jetbrains.kotlin.plugin.serialization" && ver != null) {
                useModule("org.jetbrains.kotlin:kotlin-serialization:${ver}")
            }
        }
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // Aliyun mirror FIRST (CN-hosted, not rate-limited from this sandbox).
        maven { url = uri("https://maven.aliyun.com/repository/public") }
        maven { url = uri("https://maven.aliyun.com/repository/google") }
        google()
        mavenCentral()
        // Google's read-through mirror of Maven Central as a final fallback.
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
    }
}

rootProject.name = "Threshold"
include(":app")
