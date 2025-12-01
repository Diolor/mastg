---
platform: android
title: x
id: MASTG-DEMO-00de
code: [kotlin]
test: MASTG-TEST-02te
---

### Sample

The code snippet below shows a sample that uses a WebView to load sensitive data into the cache and then performs a cleanup with `WebStorage` api.

{{ MainActivityWebView.kt # MastgTestWebView.kt # AndroidManifest.xml }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button in the app
5. Wait for the Frida script to capture the WebView cleanup calls
6. Stop the script by quitting the Frida CLI

{{ hooks.js # run.sh }}

### Observation

The output shows all instances of `deleteAllData()` of `WebStorage` called at runtime. A backtrace is also provided to help identify the location in the code.

{{ output.json }}

### Evaluation

The test **succeeds** as the application properly cleans up all storage data from the WebView cache using the `WebStorage` API.

{{ evaluate.sh }}

