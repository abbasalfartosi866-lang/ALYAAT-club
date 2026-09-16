# بناء APK/AAB في Android Studio

1. استضف نظام V4 على رابط HTTPS.
2. افتح `android/app/build.gradle.kts`.
3. غيّر:

`https://YOUR-DOMAIN.example`

إلى رابط النظام الحقيقي.
4. افتح مجلد `android` في Android Studio واتركه ينفذ Gradle Sync.
5. من Build اختر Generate App Bundles or APKs.

> هذا المصدر يحتاج Android Studio/Android SDK حتى يتم تجميع APK/AAB. لم يتم تضمين ملف APK جاهز داخل الحزمة لأن بيئة البناء الحالية لا تحتوي Android SDK/Gradle.
