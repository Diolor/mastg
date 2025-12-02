---
title: Webviews Cleanup
alias: android-webviews-cleanup
id: MASTG-BEST-00be // TODO allocate real ID
platform: android
---

Android WebViews cache data when the server responds with specific `Cache-Control` headers that instruct the browser to cache the content. 
If a WebView processes sensitive data, you should ensure that no residual information remains on the device (disk and/or RAM) once the WebView is no longer required.

Prefer server-side cache prevention using headers such as `Cache-Control: no-cache` to avoid storing sensitive content. 
If server-side control is not possible, or as an supplementary control, explicitly clear the WebView cache and related data after use to reduce the risk of exposing sensitive information.

@MASTG-KNOW-0018 describes the different storage areas used by WebViews.