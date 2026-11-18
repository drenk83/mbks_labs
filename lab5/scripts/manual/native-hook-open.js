'use strict';

// Демонстрация обратной стороны: приложение само вызывает нативную функцию
// libc, а Frida её перехватывает. Печатаются только открытия .eml, иначе
// openat в почте слишком шумный.
// Запускать attach до открытия письма, иначе onCreate уже прошёл.

var NEEDLE = 'lab5-external.eml';
var libc = Process.getModuleByName('libc.so');
var busy = false;

function hook(name, pathIndex) {
  var addr = libc.findExportByName(name);
  if (addr === null) {
    console.log('[hook] ' + name + ': not found');
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      if (busy) {
        return;
      }
      var p = args[pathIndex];
      if (p.isNull()) {
        return;
      }
      var path = p.readCString();
      if (!path || path.indexOf(NEEDLE) === -1) {
        return;
      }
      busy = true;
      try {
        console.log('[hook] ' + name + '("' + path + '") tid=' + this.threadId);
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress).slice(0, 8).join('\n'));
      } finally {
        busy = false;
      }
    }
  });
  console.log('[hook] attached ' + name + ' @ ' + addr);
}

hook('openat', 1);
hook('open', 0);
hook('fopen', 0);
