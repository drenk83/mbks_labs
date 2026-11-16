'use strict';

send({ event: 'script-loaded' });

// Трасса чтения .eml и загрузки четырёх .so. События уходят в stdout Frida через send.
// Итоговый прогон вызывает только armJava: подмена loadLibrary, EyeNative и dlopen процесс роняют.

var WATCHED = [
  'libjingle_peerconnection_so.so',
  'libYandexSpeechKitJni.4.15.7.so',
  'libcamera360-arcadia.so',
  'libeye.so'
];

// Одна строка трассы: имя события, время и поля.
function emit(event, fields) {
  var row = { event: event, t: Date.now() };
  if (fields) {
    Object.keys(fields).forEach(function (key) {
      row[key] = fields[key];
    });
  }
  send(row);
}

var entered = {};

// Первый вход в JNI-экспорт. Повтор того же символа не пишется.
function noteNative(library, symbol) {
  var key = library + ' ' + symbol;
  if (entered[key]) {
    return;
  }
  entered[key] = 1;
  emit('native-enter', { library: library, symbol: symbol });
}

// Хуки на уже загруженный .so: только JNI_OnLoad и Java_, не больше 24 экспортов.
function hookExports(name) {
  var mod = Process.findModuleByName(name);
  if (!mod) {
    return;
  }
  if (entered['mapped ' + name]) {
    return;
  }
  entered['mapped ' + name] = 1;
  emit('library-mapped', { name: name, base: mod.base.toString(), size: mod.size });
  var attached = 0;
  mod.enumerateExports().forEach(function (exp) {
    if (attached >= 24) {
      return; // потолок, чтобы не повесить хук на сотни Java_
    }
    if (exp.type !== 'function') {
      return;
    }
    if (exp.name.indexOf('JNI_OnLoad') !== 0 && exp.name.indexOf('Java_') !== 0) {
      return;
    }
    try {
      Interceptor.attach(exp.address, {
        onEnter: function () {
          noteNative(name, exp.name);
        }
      });
      attached += 1;
    } catch (err) {
      emit('hook-error', { library: name, symbol: exp.name, error: String(err) });
    }
  });
  emit('library-hooks', { name: name, java_exports_hooked: attached });
}

// Не вызывается из armJava: подмена loadLibrary роняет WebView письма.
function hookLoad() {
  var System = Java.use('java.lang.System');
  var loadLibrary = System.loadLibrary.overload('java.lang.String');
  loadLibrary.implementation = function (lib) {
    var name = String(lib);
    emit('loadLibrary', { lib: name });
    var result = loadLibrary.call(this, lib);
    if (name.indexOf('camera360') !== -1 || name === 'eye' || name.indexOf('jingle') !== -1 || name.indexOf('SpeechKit') !== -1 || name.indexOf('YandexSpeech') !== -1) {
      WATCHED.forEach(hookExports);
    }
    return result;
  };
  var load = System.load.overload('java.lang.String');
  load.implementation = function (path) {
    emit('systemLoad', { path: String(path) });
    var result = load.call(this, path);
    WATCHED.forEach(hookExports);
    return result;
  };
}

// action, type, data и начало EXTRA_TEXT для строки onCreate.
function intentText(intent) {
  if (intent === null) {
    return 'null';
  }
  var data = intent.getDataString();
  var action = intent.getAction();
  var type = intent.getType();
  var extra = '';
  try {
    var text = intent.getStringExtra('android.intent.extra.TEXT');
    if (text !== null) {
      extra = String(text).slice(0, 240);
    }
  } catch (err) {
    extra = 'extra-error';
  }
  return 'action=' + action + ' type=' + type + ' data=' + data + ' text=' + extra;
}

// Не вызывается из armJava: подмена EyeNative убивает процесс.
function hookNativeWrappers() {
  try {
    var Eye = Java.use('com.yandex.eye.nativebits.EyeNative');
    Eye.setCameraYUVBuffer.implementation = function () {
      emit('eye.setCameraYUVBuffer', { args: arguments.length });
      return this.setCameraYUVBuffer.apply(this, arguments);
    };
    Eye.processBufferBug.implementation = function () {
      emit('eye.processBufferBug', { args: arguments.length });
      return this.processBufferBug.apply(this, arguments);
    };
  } catch (err) {
    emit('hook-skip', { target: 'EyeNative', error: String(err) });
  }
  try {
    var Kit = Java.use('ru.yandex.speechkit.BaseSpeechKit');
    Kit.native_init.implementation = function (context, key) {
      var text = String(key);
      emit('speechkit.native_init', { key_len: text.length, key_prefix: text.slice(0, 8) });
      return this.native_init(context, key);
    };
  } catch (err2) {
    emit('hook-skip', { target: 'BaseSpeechKit', error: String(err2) });
  }
  try {
    var Opus = Java.use('ru.yandex.speechkit.internal.OggOpusEncoder');
    Opus.native_init.implementation = function (handle) {
      emit('speechkit.oggopus.native_init', { handle: String(handle) });
      return this.native_init(handle);
    };
  } catch (err3) {
    emit('hook-skip', { target: 'OggOpusEncoder', error: String(err3) });
  }
}

// Снимок «библиотека уже в карте?». В лог уходит число watched.
function snapshotWatched(reason) {
  var found = 0;
  try {
    Process.attachModuleObserver({
      onAdded: function (mod) {
        var before = entered['mapped ' + mod.name];
        watchAdded(mod);
        if (!before && entered['mapped ' + mod.name]) {
          found += 1;
        }
      }
    });
  } catch (err) {
    emit('hook-skip', { target: 'snapshot', error: String(err) });
    return;
  }
  emit('snapshot', { reason: reason, watched: found });
}

// onCreate одной активности. bundleNull нужен сканеру: при null он грузит camera360.
function hookOneCreate(className, after) {
  var Cls = Java.use(className);
  var onCreate = Cls.onCreate.overload('android.os.Bundle');
  onCreate.implementation = function (bundle) {
    emit('activity.onCreate', {
      class: className,
      intent: intentText(this.getIntent()),
      bundleNull: bundle === null
    });
    var result = onCreate.call(this, bundle);
    if (after) {
      after();
    }
    return result;
  };
}

// EmlActivity, сканер и openInputStream. Общий Activity.onCreate ронял WebView.
function hookIntents() {
  try {
    hookOneCreate('com.yandex.mail.eml.EmlActivity');
  } catch (err) {
    emit('hook-skip', { target: 'EmlActivity', error: String(err) });
  }
  try {
    hookOneCreate('com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity', function () {
      // Два снимка: сразу после onCreate и через 1,5 с, когда .so уже могла отобразиться.
      snapshotWatched('after DocScannerCameraActivity.onCreate');
      setTimeout(function () {
        snapshotWatched('1.5s after DocScannerCameraActivity.onCreate');
      }, 1500);
    });
  } catch (err2) {
    emit('hook-skip', { target: 'DocScannerCameraActivity', error: String(err2) });
  }

  var Resolver = Java.use('android.content.ContentResolver');
  var openInputStream = Resolver.openInputStream.overload('android.net.Uri');
  openInputStream.implementation = function (uri) {
    emit('openInputStream', { uri: String(uri) });
    return openInputStream.call(this, uri);
  };
}

// Не вызывается из armJava: android_dlopen_ext в Frida 17.4 роняет почту.
function hookDlopen() {
  var name = 'android_dlopen_ext';
  var addr = Module.findGlobalExportByName(name);
  if (!addr) {
    emit('hook-skip', { target: name, error: 'export missing' });
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      var path = '';
      try {
        path = args[0].readCString();
      } catch (err) {
        path = '';
      }
      if (!path) {
        return;
      }
      if (path.indexOf('speech') !== -1 || path.indexOf('jingle') !== -1 || path.indexOf('camera360') !== -1 || path.indexOf('libeye') !== -1 || path.indexOf('Yandex') !== -1) {
        emit('dlopen', { path: path });
        this.hit = true;
      }
    },
    onLeave: function () {
      if (this.hit) {
        WATCHED.forEach(hookExports);
      }
    }
  });
}

// Опрос карты: в лог только четыре библиотеки варианта, не все модули процесса.
function listWatched() {
  try {
    Process.enumerateModules().forEach(function (mod) {
      var n = mod.name;
      if (n.indexOf('camera360') !== -1 || n === 'libeye.so' || n.indexOf('jingle_peerconnection') !== -1 || n.indexOf('SpeechKit') !== -1 || n.indexOf('YandexSpeech') !== -1) {
        emit('module', { name: n, base: mod.base.toString(), size: mod.size });
      }
    });
  } catch (err) {
    emit('enum-error', { error: String(err) });
  }
}

// Рабочие хуки сессии. loadLibrary не подменяем: из-за этого не создаётся WebView.
// .so ищем опросом карты раз в 500 мс, после честной загрузки самим приложением.
function armJava() {
  emit('java-ready', {});
  try {
    emit('stage', { name: 'intents' });
    hookIntents();
  } catch (err3) {
    emit('hook-skip', { target: 'intents', error: String(err3) });
  }
  setInterval(function () {
    listWatched();
    WATCHED.forEach(hookExports);
  }, 500);
  try {
    emit('stage', { name: 'modules' });
    snapshotWatched('at hooks-installed');
  } catch (err4) {
    emit('enum-error', { error: String(err4) });
  }
  try {
    emit('stage', { name: 'exports' });
    WATCHED.forEach(hookExports);
  } catch (err5) {
    emit('hook-skip', { target: 'exports', error: String(err5) });
  }
  emit('hooks-installed', {});
}

// Модуль только что добавили. Чужие .so отбрасываются, свои сразу хукаются.
function watchAdded(mod) {
  var n = mod.name;
  if (n.indexOf('camera360') === -1 && n !== 'libeye.so' && n.indexOf('jingle_peerconnection') === -1 && n.indexOf('SpeechKit') === -1 && n.indexOf('YandexSpeech') === -1) {
    return;
  }
  emit('module-added', { name: n, path: mod.path, base: mod.base.toString(), size: mod.size });
  try {
    hookExports(n);
  } catch (err) {
    emit('hook-skip', { target: n, error: String(err) });
  }
}

var observerInstalled = false;

// Старт. Observer модулей один раз. Пока Java нет, повтор через 400 мс: spawn до неё не доходит.
function main() {
  if (!observerInstalled) {
    observerInstalled = true;
    try {
      Process.attachModuleObserver({
        onAdded: function (mod) {
          watchAdded(mod);
        }
      });
      emit('observer', { ok: true });
    } catch (err) {
      emit('observer', { ok: false, error: String(err) });
    }
  }
  var available = false;
  var reason = '';
  try {
    available = !!Java.available;
  } catch (err2) {
    reason = String(err2);
  }
  emit('main', { javaAvailable: available, reason: reason });
  if (!available) {
    setTimeout(main, 400);
    return;
  }
  try {
    Java.perform(armJava);
  } catch (err2) {
    emit('java-error', { error: String(err2) });
    setTimeout(main, 400);
  }
}

setImmediate(main);
