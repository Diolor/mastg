Java.perform(() => {
  console.log('Enumerating chromium...');
  let methods = Java.enumerateMethods('com.android.webview.chromium.*!deleteAllData')
  console.log(JSON.stringify(methods, null, 2))

  let method = methods[0]
  let loader = method.loader;
  let clazz = method.classes[0].name;

  Java.classFactory.loader = loader;

  const WebStorageAdapter = Java.use(clazz);
  WebStorageAdapter.deleteAllData.implementation = function() {
    console.log('WebStorage.deleteAllData() called');
    return this.deleteAllData();
  }
});