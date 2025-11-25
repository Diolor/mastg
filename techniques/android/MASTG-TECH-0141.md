---
title: Inspecting webview storage
platform: android
---

WebViews in Android applications can store data in various storage areas such as DOM storage (local and session storage), WebSQL, IndexedDB, and Cookies.

To inspect these storage areas, you can use the Chrome DevTools and remotely debug the WebView via Chrome as described in [Debugging WebViews](https://developer.android.com/topic/webview/debugging).

After having Webview debugging and inspection capabilities from Chrome as described in the link above, you can select the `Application` tab in the Chrome DevTools. Under storage, you will find storage areas such as Local, Session, Extension, Shared, and Cache Storages, as well as access to IndexedDB, Cookies, and WebSQL.

You may click around these to inspect their contents. For example, Local Storage may contain key-value pairs saved by the webview.