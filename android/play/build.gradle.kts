// Root build file — just declares the AGP version for the :app module to
// apply. Pinned to 8.13.2 (latest 8.x stable as of this writing, already
// compatible with the Gradle 8.14 wrapper distribution and with JDK 21;
// see gradle/wrapper/gradle-wrapper.properties for the Gradle pin).
plugins {
    id("com.android.application") version "8.13.2" apply false
}
