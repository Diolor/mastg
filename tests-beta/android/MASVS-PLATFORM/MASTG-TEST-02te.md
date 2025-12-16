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

This test verifies whether the application cleans up sensitive information used by WebViews. @MASTG-KNOW-0018 describes the storage areas used by WebViews and the challenges of evaluating their cleanup.

- When `WebSettings.setAppCacheEnabled()` is enabled or [`WebSettings.setCacheMode()`](https://developer.android.com/reference/android/webkit/WebSettings#setCacheMode(int)) is any value other than [`WebSettings.LOAD_NO_CACHE`](https://developer.android.com/reference/kotlin/android/webkit/WebSettings#LOAD_NO_CACHE:kotlin.Int), [`WebView.clearCache(includeDiskFiles = true)`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean)) should be called.
- When [`WebSettings.setDomStorageEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setDomStorageEnabled(boolean)) is enabled, [`WebStorage.deleteAllData()`](https://developer.android.com/reference/android/webkit/WebStorage#deleteAllData()) should be called.
- When [`WebSettings.setDatabaseEnabled()`](https://developer.android.com/reference/android/webkit/WebSettings#setDatabaseEnabled(boolean)) is enabled, [`WebStorage.deleteAllData()`](https://developer.android.com/reference/android/webkit/WebStorage#deleteAllData()) should be called.
- When [`CookieManager.setAcceptCookie()`](https://developer.android.com/reference/android/webkit/CookieManager#setAcceptCookie(boolean)) is not explicitly set to `false` (default is set to `true`), [`CookieManager.removeAllCookies(ValueCallback<Boolean> ...)`](https://developer.android.com/reference/android/webkit/CookieManager#removeAllCookies(android.webkit.ValueCallback%3Cjava.lang.Boolean%3E)) should be called.

In all the above cases, if specific storage areas are enabled but cleanup methods are not called, sensitive data may be retained beyond its intended lifetime.

!!! Warning
    This test scopes out Storage areas such as [**SQLite Wasm**](https://developer.chrome.com/blog/sqlite-wasm-in-the-browser-backed-by-the-origin-private-file-system) and other APIs used by Origin Private File System (OPFS).

## Steps

1. Reverse engineer the app and use @MASTG-TECH-0014 to inspect WebView storage enablement APIs for the target WebView. Alternatively, install and run the app with @MASTG-TECH-0033 to target WebView storage enablement APIs and navigate to the WebView you want to evaluate.
2. Optionally, use @MASTG-TECH-0142 to manually inspect the storage areas used by the WebView and their contents. Manually enumerate if sensitive data is present. Note that the webview could store sensitive data **after** the observation moment.
3. Use @MASTG-TECH-0033 to target WebView cleanup APIs and save the output.

## Observation

The output should list the locations in the app where:

1. The WebView enables particular storage areas.
2. Cleanup APIs are used during the current execution, or the lack of them.
3. Optionally, the information on whether the WebView actually stores sensitive data.

## Evaluation

The test case passes if all Storage APIs are configured to deny storage.
The test case also passes if the Storage APIs are enabled and their **relevant** cleanup APIs are called.
The test case fails if Storage APIs are enabled and their **relevant** cleanup APIs are **not** called.

!!! note
    The optional observation number 3 can be used to determine whether the WebView stores sensitive data and reduce false negatives.