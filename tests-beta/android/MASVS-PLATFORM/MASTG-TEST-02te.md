---
platform: android
title: Testing WebViews Cleanup
id: MASTG-TEST-02te // TODO replace with real ID
type: [dynamic, manual]
weakness: MASWE-0118
profiles: [L1, L2]
prerequisites:
- identify-sensitive-data
---

## Overview

This test verifies that the application cleans up sensitive information used by WebViews.

Android WebViews cache data when the server responds with specific `Cache-Control` headers that instruct the browser to cache the content. This cache is saved in the device's disk and/or RAM. If the WebView is handling sensitive information, it is crucial to clear the cache when the WebView is no longer needed to delete any locally stored files.

On server-side responses, the `Cache-Control: no-cache` can be used to indicate that an application should not cache particular content. If this header is not set or cannot be set, then the cache should be cleared. 

### Sensitive information storage areas

Sensitive information could be found or saved in several areas of a website, including, but not limited to:

- DOM storage (local and session storage)
- WebSQL (deprecated and removed in Chrome)
- IndexedDB
- Cookies (i.e., persistent, session, secure)
- other files stored locally backed by the Origin Private File System (OPFS), such as the SQLite Wasm database

> Note: WebSQL was deprecated in Android when version 15 was released. To learn more about the World Wide Web Consortium (W3C) recommendations, visit the [deprecation note](https://developer.android.com/about/versions/15/deprecations#websql-webview)

### Clearing methods

Clearing methods can be generic or granular and vary depending on the storage area that should be purged or the application's functionality.

- **Cached files**: [`WebView.clearCache(includeDiskFiles = true)`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean)) method can be called to delete both the RAM cache and files stored locally (i.e., images, JS, CSS). This is a per-application operation that clears the cache for all WebViews.
- **WebStorage APIs**: [`WebStorage.clearAllData()`] Clears DOM storage (local and session storage), Web SQL Database, and HTML5 Web Storage APIs, including IndexedDB.
- **Cookies**: [`CookieManager.removeAllCookies(ValueCallback<Boolean> ...)`] Clears all cookies.
- **OPFS**: [`java.io.File.deleteRecursively`] Deletes the file.
- **SQLite Wasm**: [`SQLiteDatabase.delete()`] to delete rows or [`SQLiteDatabase.deleteDatabase()`] to delete the database.

## Steps

1. Install and run the app. 
2. Navigate to the webview of the mobile app you want to ensure is appropriately cleaned up.
3. Optionally, manually debug the webview by @MASTG-TECH-0141 to inspect the storage areas for their content.
4. Execute a method trace (@MASTG-TECH-0033) (using e.g. @MASTG-TOOL-0001) by attaching to the running app, targeting webview cleanup APIs, and save the output.

## Observation

The output should list the locations in the app where webview cleanup APIs are used during the current execution.

## Evaluation

The test case fails if you can find sensitive data being logged using those APIs.