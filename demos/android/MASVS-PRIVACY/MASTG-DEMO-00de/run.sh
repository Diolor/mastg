NO_COLOR=true semgrep -c ../../../../rules/mastg-android-manifest-cleartext.yml ./AndroidManifest_reversed.xml > output.txt

NO_COLOR=true semgrep -c ../../../../rules/mastg-android-webview-bridges.yml ./MastgTestWebView_reversed.java > output2.txt