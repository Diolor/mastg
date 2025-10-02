package org.owasp.mastestapp

import android.content.Context
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.JavascriptInterface
import android.widget.Toast

class MastgTestWebView (private val context: Context){

    // Insecure demo JS bridge for testing (do NOT use in production)
    inner class Bridge {
        @JavascriptInterface
        fun echo(msg: String): String {
            return "echo:$msg"
        }

        @JavascriptInterface
        fun showToast(msg: String) {
            Toast.makeText(context, "JS says: $msg", Toast.LENGTH_SHORT).show()
        }
    }

    fun mastgTest(webView: WebView) {
        // Intentionally insecure WebView demo matching 00te/02te guidance
        val demoHtml = """
            <!doctype html>
            <html>
              <head>
                <meta charset='utf-8'>
                <title>MAS WebView Demo</title>
              </head>
              <body>
                <h3>MAS WebView JS Bridge Demo (insecure)</h3>
                <button onclick="MASBridge.showToast('Hello from JS!')">Call Android Toast</button>
                <button onclick="(async () => {
                  try {
                    const res = MASBridge.echo('ping');
                    document.getElementById('out').textContent = res;
                  } catch (e) { document.getElementById('out').textContent = 'error:' + e; }
                })()">Echo</button>
                <p id='out'></p>
              </body>
            </html>
        """.trimIndent()

        webView.apply {
            // Enable JavaScript (part of the failing conditions for the test)
            settings.javaScriptEnabled = true

            // Add an exposed JS interface (part of the failing conditions for the test)
            addJavascriptInterface(Bridge(), "MASBridge")

            // Basic client to keep navigation inside the WebView
            webViewClient = object : WebViewClient() {}

            // Load HTML under a cleartext base URL to emulate mixed conditions (requires usesCleartextTraffic=true to fetch network, but base URL is enough for origin in this inline demo)
            loadDataWithBaseURL(
                "http://insecure.example/", // intentional cleartext origin for the demo
                demoHtml,
                "text/html",
                "utf-8",
                null
            )
        }
    }

}
