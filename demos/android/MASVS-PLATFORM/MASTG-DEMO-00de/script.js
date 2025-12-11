function enumerateDeleteAllDataMethod() {
  return Java.enumerateMethods('com.android.webview.chromium.*!deleteAllData')[0]
}

Java.perform(() => {
  console.log('Enumerating chromium...');

  if (enumerateDeleteAllDataMethod() === undefined) {
    console.log('Bring WebStorage to memory so we can hook its deleteAllData() method.');
    // If WebStorage is not yet initialized, bring it to memory.
    Java.use("android.webkit.WebStorage").getInstance()
  }

  const method = enumerateDeleteAllDataMethod()
  Java.classFactory.loader = method.loader;

  const WebStorageAdapter = Java.use(method.classes[0].name);
  WebStorageAdapter.deleteAllData.implementation = function () {
    console.log('WebStorage.deleteAllData() called');
    return this.deleteAllData();
  }

  console.log('WebStorage.deleteAllData() hooked.');
});