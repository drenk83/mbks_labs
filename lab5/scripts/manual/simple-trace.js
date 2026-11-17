'use strict';

// Упрощённая трасса для 09_frida.sh: только EmlActivity.onCreate
// и ContentResolver.openInputStream. Без module observer и setInterval,
// чтобы не ронять процесс почты.

send({ event: 'script-loaded' });

Java.perform(function () {
  try {
    var Eml = Java.use('com.yandex.mail.eml.EmlActivity');
    var onCreate = Eml.onCreate.overload('android.os.Bundle');
    onCreate.implementation = function (bundle) {
      var intent = this.getIntent();
      send({
        event: 'EmlActivity.onCreate',
        action: intent ? String(intent.getAction()) : null,
        type: intent ? String(intent.getType()) : null,
        data: intent && intent.getData() ? String(intent.getData()) : null,
        bundleNull: bundle === null
      });
      return onCreate.call(this, bundle);
    };
  } catch (err) {
    send({ event: 'hook-skip', target: 'EmlActivity', error: String(err) });
  }

  try {
    var Scanner = Java.use('com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity');
    var scannerOnCreate = Scanner.onCreate.overload('android.os.Bundle');
    scannerOnCreate.implementation = function (bundle) {
      send({ event: 'DocScannerCameraActivity.onCreate', bundleNull: bundle === null });
      return scannerOnCreate.call(this, bundle);
    };
  } catch (errScanner) {
    send({ event: 'hook-skip', target: 'DocScannerCameraActivity', error: String(errScanner) });
  }

  try {
    var Resolver = Java.use('android.content.ContentResolver');
    var openInputStream = Resolver.openInputStream.overload('android.net.Uri');
    openInputStream.implementation = function (uri) {
      send({ event: 'openInputStream', uri: String(uri) });
      return openInputStream.call(this, uri);
    };
  } catch (err2) {
    send({ event: 'hook-skip', target: 'openInputStream', error: String(err2) });
  }

  send({ event: 'hooks-installed' });
});
