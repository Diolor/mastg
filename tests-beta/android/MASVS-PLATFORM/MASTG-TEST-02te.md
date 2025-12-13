---
platform: android
title: Testing WebViews Cleanup
id: MASTG-TEST-02te // TODO allocate real ID
type: [dynamic, manual]
weakness: MASWE-0118
profiles: [L1, L2]
best-practices: [MASTG-BEST-00be]
prerequisites:
- identify-sensitive-data
---

## Overview

This test verifies whether the application cleans up sensitive information used by WebViews. @MASTG-KNOW-0018 describes the different storage areas used by WebViews.

- When `WebSettings.setAppCacheEnabled()` is enabled or [`WebSettings.setCacheMode()`](https://developer.android.com/reference/android/webkit/WebSettings#setCacheMode(int)) is any value other than [`LOAD_NO_CACHE`](https://developer.android.com/reference/kotlin/android/webkit/WebSettings#LOAD_NO_CACHE:kotlin.Int), [`WebView.clearCache(includeDiskFiles = true)`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean)) should be called.
- When [`setDomStorageEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setDomStorageEnabled(boolean)) is enabled, [`WebStorage.deleteAllData()`](https://developer.android.com/reference/android/webkit/WebView#clearFormData()) should be called.
- When [`WebSettings.setDatabaseEnabled()`](https://developer.android.com/reference/android/webkit/WebSettings#setDatabaseEnabled(boolean)) is enabled, [`WebStorage.deleteAllData()`](https://developer.android.com/reference/android/webkit/WebView#clearFormData()) should be called.
- When [`CookieManager.setAcceptCookie()`](https://developer.android.com/reference/android/webkit/CookieManager#setAcceptCookie(boolean)) is not explicitly set to `false` (default is set to `true`), [`CookieManager.removeAllCookies(ValueCallback<Boolean> ...)`](https://developer.android.com/reference/android/webkit/CookieManager#removeAllCookies(android.webkit.ValueCallback%3Cjava.lang.Boolean%3E)) should be called.

In all above cases, if specific storage areas are enabled but the cleanup methods are not called, sensitive data may be stored past the end of their intended lifetime.

## Steps

1. Install and run the app.
2. Navigate to the webview of the mobile app you want to ensure is appropriately cleaned up.
3. Optionally, manually debug the webview by @MASTG-TECH-0141 to inspect the storage areas for their content.
4. Use @MASTG-TECH-0033 by attaching to the running app, targeting webview cleanup APIs, and save the output.

## Observation

The output should list the locations in the app where WebView cleanup APIs are used during the current execution or the lack of them.

## Evaluation

The test case fails if you can find sensitive data being logged using those APIs.
