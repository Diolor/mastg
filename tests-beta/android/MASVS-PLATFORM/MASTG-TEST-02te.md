---
platform: android
title: Native code Exposed Through WebViews
id: MASTG-TEST-02te
type: [static]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013, MASTG-BEST-0022]
profiles: [L1, L2]
---

## Overview

Android apps that have WebViews may also have WebView – Native bridges. These bridges can be added via the `addJavascriptInterface` method in the `WebView` class. They enable two-way communication: native code can pass data to the WebView, and JavaScript in the WebView can call into native code. Any website loaded inside the WebView, including those outside the organization's control, can access these bridges (if configured) whenever JavaScript is enabled with `setJavaScriptEnabled(true)`.

The weakness could become a vulnerability if the WebView allows unencrypted (non-TLS) traffic (i.e., HTTPS) in combination with an XSS attack.

> Note:
> Applications targeting API level 16 or earlier are particularly at risk of attack because this method can be used to allow JavaScript to control the host application.

**Example Attack Scenario:**

1. An attacker exploits an XSS vulnerability in a website loaded in the WebView.
2. The attacker uses the XSS vulnerability to execute JavaScript code that calls methods exposed by the `addJavascriptInterface` method.
3. The attacker can then read (sensitive) data or perform actions on behalf of the user, depending on the methods exposed by the interface.

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

The test fails automatically if all the following are true:

- the application is targeting API level 16 or lower.
- `addJavascriptInterface` is used at least once.

The test also fails automatically if all the following are true:

- `usesCleartextTraffic` is not set in the `AndroidManifest.xml` file and the app targets API level 27 or lower, or `usesCleartextTraffic` is `true` and the app targets API level 28 or above.
- `setJavaScriptEnabled` is `true`.
- `addJavascriptInterface` is used at least once.

The test also fails, after evaluating the `addJavascriptInterface` method(s) and `@JavascriptInterface` annotation(s), if all the following are true:

- Sensitive data can be read through the interface methods.
- Actions that can affect the confidentiality, integrity, or availability of the application can be performed via the interface methods.

**Pass:**

The test passes if any of the following are true:

- `setJavaScriptEnabled` is `false` or not used at all.
- `addJavascriptInterface` is not used at all.