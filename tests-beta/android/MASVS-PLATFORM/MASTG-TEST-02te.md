---
platform: android
title: Testing WebViews Cleanup
id: MASTG-TEST-02te // TODO replace with real ID
type: [static, dynamic]
weakness: TODO // review https://github.com/OWASP/maswe/pull/12
profiles: [L1, L2]
prerequisites:
- identify-sensitive-data
---

## Overview

This test verifies that the application cleans up sensitive information used by WebViews.

Android WebViews cache data when the server responds with specific `Cache-Control` headers that instruct the browser to cache the content. This cache is saved in the device's disk and/or RAM. If the WebView is handling sensitive information, it is crucial to clear the cache when the WebView is no longer needed to delete any locally stored files.

On server-side responses, the `Cache-Control: no-cache` can used to indicate that an application should not cache particular content. If this header is not or cannot be set, then the cache should be cleared. 

### Sensitive information storage areas

Sensitive information could be found or saved in several areas of a website, including, but not limited to:

- DOM storage (local and session storage)
- WebSQL (deprecated and removed in Chrome)
- IndexedDB
- Cookies (i.e. persistent, session, secure)
- other files stored locally backed by the Origin Private File System (OPFS), such as the SQLite Wasm database

> Note: WebSQL was deprecated in Android when version 15 was released. To learn more about the World Wide Web Consortium (W3C) recommendations, visit the [deprecation note](https://developer.android.com/about/versions/15/deprecations#websql-webview)

### Clearing methods

Clearing methods can be generic or granular and vary depending on the storage area that should be purged or the application functionality.

- **Cached files**: [`WebView.clearCache(includeDiskFiles = true)`](https://developer.android.com/reference/android/webkit/WebView#clearCache(boolean)) method can be called to delete both the RAM cache and files stored locally (i.e., images, JS, CSS). This is a per-application operation, so it will clear the cache for all WebViews used.
- **WebStorage APIs**: [`WebStorage.clearAllData()`] Clears DOM storage (local and session storage), Web SQL Database and HTML5 Web Storage APIs, including IndexedDB.
- **Cookies**: [`CookieManager.removeAllCookies(ValueCallback<Boolean> ...)`] Clears all cookies.
- **OPFS**: [`java.io.File.deleteRecursively`] Deletes the file.
- **SQLite Wasm**: [`SQLiteDatabase.delete()`] to delete rows or [`SQLiteDatabase.deleteDatabase()`] to delete the database.

## Steps

1. 


## Observation


## Evaluation
