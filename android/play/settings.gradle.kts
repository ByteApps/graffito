// Google Play AAB build wrapper for the Graffito Android app.
//
// This is a THIN Gradle shim around the real build: the app itself is a
// Rust cdylib (crate chain-notes-app, built by cargo-apk for the sideload
// APK path — see ../../src and ../../Cargo.toml's [package.metadata.android]).
// cargo-apk only produces APKs; Google Play requires an Android App Bundle
// (.aab) for new app uploads, and AGP's bundleRelease task is the only
// practical way to produce one. This module has NO Java/Kotlin sources —
// it just repackages the .so cargo-apk already builds (staged into
// app/src/main/jniLibs by scripts/build-play-bundle.sh) plus the shared
// launcher-icon resources and a hand-mirrored manifest.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "graffito-play"
include(":app")
