pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        // Aliyun kept as a fallback (faster from CN, but flaky).
        maven { url = uri("https://maven.aliyun.com/repository/gradle-plugin") }
        maven { url = uri("https://maven.aliyun.com/repository/public") }
        maven { url = uri("https://maven.aliyun.com/repository/google") }
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
        google()
        mavenCentral()
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
        maven { url = uri("https://maven.aliyun.com/repository/public") }
        maven { url = uri("https://maven.aliyun.com/repository/google") }
    }
}

rootProject.name = "Threshold"
include(":app")
