plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "org.sempersupra.aar.golden.kotlin"
    compileSdk = 35

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    defaultConfig {
        applicationId = "org.sempersupra.aar.golden.kotlin"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        create("obfuscated") {
            initWith(getByName("release"))
            isMinifyEnabled = true
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "aar-obfuscation-rules.pro",
            )
            matchingFallbacks += listOf("release")
        }
        // R8's -dontshrink also affects optimization; these are a controlled
        // *nested sequence*, not an orthogonal 2x2x2 factorial.
        create("renameOnly") {
            initWith(getByName("obfuscated"))
            proguardFiles("aar-rename-only.pro")
            matchingFallbacks += listOf("release")
        }
        create("shrinkOnly") {
            initWith(getByName("obfuscated"))
            proguardFiles("aar-shrink-only.pro")
            matchingFallbacks += listOf("release")
        }
        create("shrinkOptimize") {
            initWith(getByName("obfuscated"))
            proguardFiles("aar-shrink-optimize.pro")
            matchingFallbacks += listOf("release")
        }
    }

    testOptions {
        unitTests.all {
            it.useJUnit()
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
