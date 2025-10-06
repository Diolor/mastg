---
platform: android
title: Native code Exposed Through WebViews
id: MASTG-DEMO-00de
code: [kotlin]
test: MASTG-TEST-02te
---

### Sample

// TODO 

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample manifest file.

{{ ../../../../rules/mastg-android-manifest-cleartext.yml }}

And another one against the reversed Java code.

{{ ../../../../rules/mastg-android-webview-bridges.yml }}

{{ run.sh }}

### Observation

// TODO

{{ output.txt # output2.txt }}

### Evaluation

// TODO