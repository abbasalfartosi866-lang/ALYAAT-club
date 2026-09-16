plugins { id("com.android.application") }

android {
    namespace = "com.alyatpolice.club"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.alyatpolice.club"
        minSdk = 24
        targetSdk = 35
        versionCode = 5
        versionName = "5.0"
        val appUrl = project.findProperty("APP_URL")?.toString() ?: "http://10.0.2.2:8000/"
        buildConfigField("String", "APP_URL", "\\\"$appUrl\\\"")
    }
    buildFeatures { buildConfig = true }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.webkit:webkit:1.12.1")
}
