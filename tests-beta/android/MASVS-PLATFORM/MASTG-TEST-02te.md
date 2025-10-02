---
platform: android
title: Native code Exposed Through WebViews
id: MASTG-TEST-02te
type: [static, dynamic]
weakness: MASWE-0069
#best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013] // TODO
profiles: [L1, L2]
---

## Overview

Android apps that have WebViews may also have WebView – Native bridges. These bridges can be added via the `addJavascriptInterface` method in the `WebView` class. They enable two-way communication: native code can pass data to the WebView, and JavaScript in the WebView can call into native code. Any website loaded inside the WebView, including those outside the organization's control, can access these bridges (if configured) whenever JavaScript is enabled with `setJavaScriptEnabled(true)`.

The weakness could become a vulnerability if the WebView allows unencrypted (non-TLS) traffic (i.e., HTTPS) in combination with an XSS attack.

> Note:
> Applications targeting API level 16 or earlier are particularly at risk of attack because this method can be used to allow JavaScript to control the host application.


**Example Attack Scenario:**

## Steps

1. Use a tool like @MASTG-TOOL-0110 to search for references to:
    - `usesCleartextTraffic` option in the AndroidManifest.xml file
    - the `setJavaScriptEnabled` method
    - the `addJavascriptInterface` method
    - the `@JavascriptInterface` annotation

## Observation

The output should contain:

1. The value of the `usesCleartextTraffic` option in the `AndroidManifest.xml` file.
2. A list of WebView instances, including the following methods and their arguments:
    - `setJavaScriptEnabled`
    - `addJavascriptInterface` and their associated classes
    - `@JavascriptInterface` and their associated methods

## Evaluation

**Fail:**

The test fails if all the following are true:

- `usesCleartextTraffic` is `true` or it's not set at all in the `AndroidManifest.xml` file, and the app targets API level 27 or lower.
- `setJavaScriptEnabled` is `true`.
- `addJavascriptInterface` is used at least once.

You should use the list of locations where `addJavascriptInterface` and `@JavascriptInterface` are used to determine whether an attacker could:

- Read sensitive data from the interface methods.
- Perform actions via the interface methods.

**Pass:**

The test passes if any of the following are true:

- `setJavaScriptEnabled` is `false` or not used at all.
- `addJavascriptInterface` is not used at all.