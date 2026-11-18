'use strict';

// Демонстрация вызова нативных функций: Frida вызывает libc в процессе почты.
// Frida 17: статических Module.getExportByName больше нет, поэтому Module
// берётся через Process.getModuleByName, а экспорт ищется у него.
// Файл письма кладёт 08_emulator.sh (подкоманда eml).

var TAG = '[native]';
var EML = '/data/data/ru.yandex.mail/files/lab5-external.eml';

function log(s) {
  console.log(TAG + ' ' + s);
}

var libc = Process.getModuleByName('libc.so');
log('libc=' + libc.path + ' base=' + libc.base + ' arch=' + Process.arch);

var getpid = new NativeFunction(libc.getExportByName('getpid'), 'int', []);
var getuid = new NativeFunction(libc.getExportByName('getuid'), 'uint', []);
var strlen = new NativeFunction(libc.getExportByName('strlen'), 'size_t', ['pointer']);
var open = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int']);
var read = new NativeFunction(libc.getExportByName('read'), 'ssize_t', ['int', 'pointer', 'size_t']);
var close = new NativeFunction(libc.getExportByName('close'), 'int', ['int']);

// getpid и Process.id — один и тот же процесс, а не вызов на хосте.
var pid = getpid();
log('getpid()=' + pid + ' Process.id=' + Process.id + ' match=' + (pid === Process.id));

// getuid совпадает с uid пакета: adb shell stat -c %u /data/data/ru.yandex.mail
log('getuid()=' + getuid());

var hello = Memory.allocUtf8String('LAB5-NATIVE-CALL');
log('strlen("LAB5-NATIVE-CALL")=' + strlen(hello));

var fd = open(Memory.allocUtf8String(EML), 0 /* O_RDONLY */);
log('open("' + EML + '", O_RDONLY)=' + fd);
if (fd < 0) {
  log('open не удался; проверь, что 08_emulator.sh eml уже выполнялся');
} else {
  var buf = Memory.alloc(512);
  var n = read(fd, buf, 512);
  log('read(fd, 512)=' + n);
  if (n > 0) {
    var text = buf.readUtf8String(Number(n));
    log('marker=' + (text.indexOf('LAB5-EML-MARKER') !== -1));
    log('first line=' + text.split('\n')[0]);
  }
  log('close(' + fd + ')=' + close(fd));
}
