'use strict';

// Сканер грузит libcamera360-arcadia.so. Показываем нативный open этой
// библиотеки. Хуки на dlopen/android_dlopen_ext и JNI-экспорты убраны:
// на этом эмуляторе они роняли процесс в libRS (rsContextCreate).
// Если библиотека уже загружена, модуль просто печатается из карты.

var LIB = 'libcamera360-arcadia.so';
var TAG = '[scanner-native]';
var mapped = false;
var pollTimer = null;
var ticks = 0;

function log(s) {
  console.log(TAG + ' ' + s);
}

function onMapped(mod, how) {
  if (mapped) {
    return;
  }
  mapped = true;
  if (pollTimer !== null) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  log('LIB MAPPED (' + how + '): ' + mod.name);
  log('path=' + mod.path);
  log('base=' + mod.base + ' size=' + mod.size);
  // Сразу снимаем хуки, чтобы не мешать сканеру после того,
  // как нужная строка уже напечатана.
  setTimeout(function () {
    try {
      Interceptor.detachAll();
      log('hooks detached');
    } catch (e) {}
  }, 0);
}

function hookOpen() {
  var libc = Process.getModuleByName('libc.so');
  [['openat', 1], ['open', 0]].forEach(function (spec) {
    var addr = libc.findExportByName(spec[0]);
    if (addr === null) {
      log(spec[0] + ' not found');
      return;
    }
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          var p = args[spec[1]];
          if (p.isNull()) {
            return;
          }
          var path = p.readCString();
          if (!path || path.indexOf('camera360') === -1) {
            return;
          }
          log(spec[0] + '("' + path + '")');
          var mod = Process.findModuleByName(LIB);
          if (mod) {
            onMapped(mod, spec[0]);
          }
        } catch (e) {}
      }
    });
    log('hooked ' + spec[0] + ' @ ' + addr);
  });
}

var existing = Process.findModuleByName(LIB);
if (existing) {
  log('already loaded at attach; для живого вызова перезапусти приложение');
  onMapped(existing, 'already loaded');
} else {
  log('armed; waiting for ' + LIB + ' (open the scanner now)');
  hookOpen();
  pollTimer = setInterval(function () {
    var mod = Process.findModuleByName(LIB);
    if (mod) {
      onMapped(mod, 'poll');
      return;
    }
    ticks++;
    if (ticks % 20 === 0) {
      log('still waiting: ' + Math.round(ticks / 4) + 's');
    }
  }, 250);
}
