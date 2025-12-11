---
platform: android
title: Testing WebViews DOM storage Cleanup
id: MASTG-TEST-02te // TODO allocate real ID
type: [dynamic, manual]
weakness: MASWE-0118
profiles: [L1, L2]
best-practices: [MASTG-BEST-00be]
prerequisites:
- identify-sensitive-data
---

## Overview

This test verifies that the application cleans up sensitive information used by WebViews in DOM storage (local and session storage). @MASTG-KNOW-0018 describes the different storage areas used by WebViews.

## Steps

1. Install and run the app.
2. Navigate to the webview of the mobile app you want to ensure is appropriately cleaned up.
3. Optionally, manually debug the webview by @MASTG-TECH-0141 to inspect the storage areas for their content.
4. Use @MASTG-TECH-0033 by attaching to the running app, targeting webview cleanup APIs, and save the output.

## Observation

The output should list the locations in the app where WebView cleanup APIs are used during the current execution or the lack of them.

## Evaluation

The test case fails if you can find sensitive data being logged using those APIs.
