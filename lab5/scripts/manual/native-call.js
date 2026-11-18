'use strict';

// Вход в две JNI-функции libcamera360-arcadia.so.
// Библиотека грузится из base.apk, observer её не видит, поэтому карта опрашивается.
// Хук функцию не подменяет. loadLibrary, EyeNative и dlopen не трогаем: они роняют почту.

var LIB = 'libcamera360-arcadia.so';
var TARGETS = [
  'Java_ru_yandex_dict_mt_libs_mobile_android_MTMobileScannerJNI_new_1TDocumentScanner',
  'Java_ru_yandex_dict_mt_libs_mobile_android_MTMobileScannerJNI_TDocumentScanner_1DetectDocumentEdges'
];

send({ event: 'script-loaded' });

function arm(mod) {
  if (arm.done) {
    return;
  }
  arm.done = true;
  send({ event: 'library-mapped', name: mod.name, base: mod.base.toString() });
  TARGETS.forEach(function (symbol) {
    var addr = mod.findExportByName(symbol);
    if (!addr) {
      send({ event: 'hook-skip', symbol: symbol });
      return;
    }
    Interceptor.attach(addr, {
      onEnter: function () {
        send({ event: 'native-enter', library: mod.name, symbol: symbol });
      }
    });
    send({ event: 'hooked', symbol: symbol });
  });
}

function findLib() {
  var found = null;
  Process.enumerateModules().forEach(function (mod) {
    if (mod.name === LIB) {
      found = mod;
    }
  });
  return found;
}

var waitingSent = false;

function poll() {
  var mod = findLib();
  if (mod) {
    arm(mod);
    return;
  }
  if (!waitingSent) {
    waitingSent = true;
    send({ event: 'waiting', library: LIB });
  }
  setTimeout(poll, 300);
}

poll();
