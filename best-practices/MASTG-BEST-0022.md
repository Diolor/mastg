---
title: Ensure WebViews within organizational control
alias: ensure-webviews-within-organizational-control
id: MASTG-BEST-0022
platform: android
---

### Recommendation

WebViews in Android allow applications to render web content, but they can introduce significant security risks if not properly managed.

Whenever possible, follow the guidance in @MASTG-BEST-0012 and load only static WebViews that are packaged within the app bundle. This approach ensures that the displayed content cannot be tampered with remotely.

If your application must display dynamic web content from the internet, ensure that all websites loaded in your WebView are secure and under your organization's control.

When you need to display content from external or untrusted domains, you should not load it directly in a WebView. Instead, open it in the user's default browser or use safer alternatives such as [Trusted Web Activities](https://developer.android.com/guide/topics/app-bundle/trusted-web-activities) or [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/). These solutions leverage the browser's isolated environment, benefiting from:

- Automatic security updates
- Strong process sandboxing
- Built-in mitigations against common web vulnerabilities (e.g., Cross-Site Scripting (XSS), Man-in-the-Middle (MITM) attacks)

To enforce domain control and prevent untrusted content from loading inside your app, apply the following control:

```kotlin
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(
        view: WebView?,
        request: WebResourceRequest?
    ): Boolean {
        val url = request?.url.toString()
        Log.d("WebView", "About to load: $url")

        // You can intercept or allow it:
        val outsideControl = isOutsideControl(url)
        if(outsideControl){
            // Handle the case where the URL is outside your control
            // For example, open it in the default browser instead
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            context.startActivity(intent)
        }
        return outsideControl // return true if you want to handle it manually
    }
}

fun isOutsideControl(url: String): Boolean {
    val trustedDomains = listOf("https://my-domain.com", "https://another-trusted-domain.com")
    return trustedDomains.none { url.startsWith(it) }
}
```

### Considerations

A trade-off of this approach is that you may lose some control over the user experience, as the user will be taken out of your app when viewing external content. However, this is a necessary compromise to ensure the security and integrity of your application.

### References

- [Android WebView Security Best Practices](https://developer.android.com/reference/android/webkit/WebView#security)
- [Google Safe Browsing Service](https://developer.android.com/develop/ui/views/layout/webapps/managing-webview)
