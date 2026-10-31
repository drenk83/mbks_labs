Министерство науки и высшего образования Российской Федерации

Санкт-Петербургский политехнический университет Петра Великого

Институт компьютерных наук и кибербезопасности

Высшая школа кибербезопасности

# ОТЧЁТ ПО ЛАБОРАТОРНОЙ РАБОТЕ № 5

## «Аудит безопасности мобильных приложений»

по дисциплине «Модели безопасности компьютерных систем»

| | |
|---|---|
| Выполнил | студент гр. 5131001/30501 Чупров Е. А. |
| Проверил | ассистент Жуковский Е. В. |

Санкт-Петербург

2026

## 1. Цель работы

Провести аудит безопасности мобильного приложения с исходным кодом и приложения без исходного кода по разделам OWASP MASVS и MSTG. Для чёрного ящика разобрать поверхность атаки в манифесте, воспроизвести обработку внешних данных, снять трассу динамической инструментации, перечислить нативные методы и сторонние библиотеки, построить поток данных и прогнать доступные средства автоматического анализа.

## 2. Вариант

Вариант 11 задания `lab5/ЛР5_Аудит_безопасности_моб_приложений.docx`.

В таблице задания белый ящик назван mvfa. Каталог с исходниками называется mfva, пакет `com.appknox.mfva`. Это демонстрационное приложение Appknox (Viren Nadkarni, GPLv3), написанное на Java. Чёрный ящик — Yandex Mail 8.81.2 из архива преподавателя `AndroidApps4Research.zip`. Сборка 8.78.1 из `AndroidApps.zip` не использовалась.

Журнал команд и наблюдений ведётся отдельно: `lab5/Журнал_действий.md`.

## 3. Стенд

Команды ниже выполнялись после `source lab5/work/env.sh`. Каталог `lab5/work/` в git не входит.

| Компонент | Версия |
|---|---|
| JDK | Temurin 21.0.13+9 |
| JADX | 1.5.6 |
| apktool | 3.0.3 |
| androguard | 4.1.4 |
| Frida и frida-server | 17.4.0, клиент из `lab5/work/venvs/frida` |
| FlowDroid | 2.15.1 |
| Trueseeing | 2.2.11 |
| APKHunt | сборка CLI, в прогоне печатает OWASP MASVS Static Analyzer |
| Эмулятор | Android Emulator 37.2.13.0, AVD `lab5_api34`, образ google_apis x86_64, API 34 |
| adb | 1.0.41 |

Два первых запуска qemu с `-gpu swiftshader_indirect` завершились падением процесса: SIGSEGV при `-memory 3072` и SIGBUS в `gfxstream::host::RenderChannelImpl::tryRead` при `-memory 2048`. Рабочий запуск:

```text
emulator -avd lab5_api34 -no-window -no-audio -no-boot-anim -no-metrics -gpu guest -memory 2048 -cores 2 -no-snapshot -feature -Vulkan
```

Загрузка гостя заняла 14495 мс (`Boot completed in 14495 ms` в `/tmp/lab5/emulator.log`), `ro.build.version.sdk` равен 34. Образ не умеет гостевой рендерер: в том же логе есть `Falling back to 'lavapipe' mode`, GLES ушёл в swangle. Этот режим не упал. Память эмулятор сам поднял до 2560 МБ. Скриншоты снимались командой `adb exec-out screencap -p`.

MobSF и SEBASTiAN на машине не запускаются: сокет Docker недоступен, прав sudo нет. ToolScript набора OWApp требует `apt-get` и Docker, его не запускал.

## 4. MASVS, MSTG и Kotlin-SCP

Ориентир отчёта — категории MASVS v1, на которые ссылается задание:

1. Архитектура и модель угроз.
2. Хранение данных и приватность.
3. Криптография.
4. Аутентификация и сессии.
5. Сетевое взаимодействие.
6. Взаимодействие с платформой.
7. Качество кода и параметры сборки.
8. Устойчивость к анализу и модификации. Для уровня L1 этот раздел не обязателен.

MSTG даёт тесты к тем же категориям. Номера отдельных тестов в отчёте не подставляются там, где по коду нельзя честно сослаться на конкретный идентификатор. Kotlin-SCP разбирает те же классы ошибок для приложений на Kotlin. mfva написан на Java, поэтому рекомендации Kotlin-SCP переносятся по смыслу: секреты не хранить в исходнике, не включать JavaScript в WebView без нужды, не открывать компоненты без разрешения, не использовать DES и MD5, не отправлять токен по HTTP.

## 5. Белый ящик: mfva

Исходники: `/home/drenk83/Documents/mbks/3/mfva-master`. Сборка `compileSdk 30`, `minSdk 25`, `targetSdk 30`, `versionName 1.0`, `versionCode 6`. Зависимости: OkHttp 3.8.0, Jedis 2.9.0, AppCompat 1.0.0. `minifyEnabled` выключен. README прямо говорит, что приложение специально содержит уязвимости для демонстрации сканера Appknox.

Динамический прогон mfva задание для белого ящика не требует. Ниже разбор по категориям и правка для каждой находки.

### 5.1. Архитектура

Точка входа — `MainActivity`. Из неё открываются `WebViewActivity` и `ApiRequestsActivity`. Отдельные экспортированные компоненты лежат рядом и не связаны с пользовательским сценарием главного экрана. Модели угроз в репозитории нет. Для учебного приложения достаточно зафиксировать, что экспортированные компоненты и сеть без TLS — это намеренная поверхность, а не забытый черновик.

Исправление: оставить один учебный экран с пояснением каждой ошибки и убрать боевые имена хостов, если приложение когда-либо ставится вне стенда.

### 5.2. Хранение данных

`AndroidManifest.xml` задаёт `android:allowBackup="true"`. Резервная копия adb забирает данные приложения, включая SharedPreferences.

Кнопка в `MainActivity` пишет случайное системное свойство в файл настроек `pref` в режиме `MODE_PRIVATE` (`getSharedPreferences("pref", 0)`):

```java
SharedPreferences pref = getApplicationContext().getSharedPreferences("pref", 0);
editor.putString(key, System.getProperty(key));
editor.commit();
```

Там оказываются `os.version`, `java.home` и соседние свойства. Сами по себе они не секрет, но вместе с резервной копией это лишняя выдача сведений об устройстве. Флага `FLAG_SECURE` в исходниках нет, содержимое экрана попадает в скриншоты и в список недавних задач. Отладочные цитаты пишутся в logcat через `Log.d("YOLO", quote)`.

Исправление: `android:allowBackup="false"`, не писать свойства окружения в preferences, убрать `Log.d` из пользовательских действий, для экранов с токеном ставить `FLAG_SECURE`.

### 5.3. Криптография

Контрольная сумма считается как MD5, а в интерфейс попадает не дайджест, а идентификатор массива. `hash.toString()` у `byte[]` не печатает байты:

```java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(quote.getBytes());
Snackbar.make(v, "MD5:" + hash.toString() + ": " + quote, Snackbar.LENGTH_SHORT).show();
```

Шифрование в `MainActivity` и тот же алгоритм в `ExportedActivity`:

```java
SecretKey keyspec = new SecretKeySpec("Gangnam!".getBytes(), "DES");
Cipher c = Cipher.getInstance("DES/ECB/ZeroBytePadding", "BC");
```

DES, режим ECB и ключ из восьми символов в исходнике не годятся для защиты данных. Провайдер `BC` в `build.gradle` не подключён и нигде не регистрируется, поэтому вызов с `"BC"` на устройстве падает и перехватывается. Параметры алгоритма от этого не становятся приемлемыми. Android Keystore не используется. MD5 без провайдера `BC` выполняется штатным провайдером, так что слабый хеш реально считается.

Исправление: AES-GCM или ChaCha20-Poly1305, ключ в Android Keystore, для целостности SHA-256. Учебную кнопку оставить только с подписью, что алгоритм заведомо слабый.

### 5.4. Аутентификация

Локальной проверки пользователя нет. `ApiRequestsActivity` отправляет зашитые `user1` и `pass1` на `http://vapi.appknox.io/tokens`. Ответный токен живёт в локальной переменной и дописывается в `TextView`. Пароль создаваемого пользователя постоянен: `pass0`. Срок жизни токена тоже показывается на экране. Отдельного выхода из сессии и привязки токена к устройству нет.

Исправление: не хранить пароль в исходнике, получать его из ввода, токен держать в `EncryptedSharedPreferences` или в Keystore и не выводить целиком в интерфейс.

### 5.5. Сеть

Все адреса в `ApiRequestsActivity` — `http://vapi.appknox.io` (`/`, `/tokens`, `/user/1`, `/user`, `/uptime`, `/uptime/s`). Клиент — `OkHttpClient` без pinning и без своего `TrustManager`. В манифесте нет `networkSecurityConfig` и нет `usesCleartextTraffic`. При `targetSdk 30` платформа с API 28 запрещает ясный текст по умолчанию, поэтому на современном устройстве запросы, скорее всего, не уйдут. Исходник при этом нарушает требование не передавать аутентификационные данные открытым каналом: заголовок `X-Auth-Token` поставлен на HTTP URL.

Исправление: только HTTPS, Network Security Config без cleartext, certificate pinning на учебный стенд, если сертификат свой.

### 5.6. Платформа

`WebViewActivity` включает JavaScript и открывает ясный текст. Своего `WebViewClient` нет, `addJavascriptInterface` нет:

```java
webView.getSettings().setJavaScriptEnabled(true);
webView.loadUrl("http://example.com");
```

На API 28+ загрузка `http://example.com` тоже может быть отвергнута политикой cleartext. Настройка JavaScript при этом уже включена.

Экспортированные компоненты:

| Компонент | exported | Разрешение в манифесте | Поведение |
|---|---|---|---|
| `ExportedActivity` | true | `com.appknox.mfva.CustomPermission` | Разрешение нигде не объявлено тегом `permission`, поэтому чужое приложение его не получит. Внутри создаётся `Jedis("localhost")` без пароля и тот же DES/ECB |
| `UnprotectedService` | true | то же необъявленное разрешение | Снаружи не вызвать |
| `UnprotectedReceiver` | true | то же разрешение | Имя обманчиво: снаружи он как раз закрыт |
| `ExportedService` | true | нет | `onBind` бросает `UnsupportedOperationException`. Это локальный отказ в обслуживании при bind |
| `ExportedReceiver` | true | нет | Слушает `BOOT_COMPLETED` и `INPUT_METHOD_CHANGED`. Разрешения `RECEIVE_BOOT_COMPLETED` у приложения нет, системный boot оно не получит. Любое приложение может послать явный broadcast. Приёмник пишет URI intent в лог и в Toast |
| `StubProvider` | true | необъявленное разрешение | Снаружи закрыт. Authority `com.example.android.datasync.provider` не совпадает с пакетом |

`WebViewActivity` и `ApiRequestsActivity` без `exported` и без intent-filter при `targetSdk 30` снаружи не запускаются.

Исправление: у `ExportedService` и `ExportedReceiver` поставить `exported="false"` или объявить signature-permission и повесить его на компонент. `onBind` должен возвращать `null`, а не бросать исключение. WebView грузить только `https`, JavaScript выключать, пока он не нужен, и ставить `WebViewClient`, который режет посторонние URL.

### 5.7. Качество кода

ProGuard выключен. Исключения криптографии и сети проглатываются и показываются через `Snackbar` с фонового потока в `ApiRequestsActivity` (`Snackbar.make` вызывается не с главного потока). `hash.toString()` показывает не хеш. Сервисы не реализуют bind.

Исправление: ошибки показывать с главного потока, хеш печатать через `BigInteger` или hex, включить сжатие кода в release, если приложение перестаёт быть учебным стендом.

### 5.8. Устойчивость

Проверок отладчика, root, подписи и целостности нет. Для MASVS L1 этот раздел не требуется. Отметить отсутствие контроля достаточно. Добавлять его в учебное приложение с намеренными ошибками не нужно: он мешает разбирать те же ошибки.

### 5.9. Соответствие Kotlin-SCP

Приложение на Java, отдельных файлов Kotlin нет. Те же правила Kotlin-SCP здесь нарушены в четырёх местах: секрет и пароль в исходнике, WebView с JavaScript и HTTP, экспортированный приёмник без разрешения, DES/ECB и MD5. Исправления совпадают с разделами 5.3–5.6.

## 6. Чёрный ящик: образец

Файл `lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk`.

| Поле | Значение |
|---|---|
| Пакет | `ru.yandex.mail` |
| versionName | 8.81.2 |
| versionCode | 105397 |
| minSdk / targetSdk | 26 / 33 |
| Размер | 136353707 байт |
| SHA-256 | `6fb616ce30b13dc911a9dcdd2ddfeb3450a4eb6cbf49a99733c5aefa8680463c` |
| Классов / методов | 59178 / 260516 (androguard) |
| Dex | пять файлов |
| Приложение | `com.yandex.mail.MailApplication` |

`allowBackup` равен false, `extractNativeLibs` равен false, `debuggable` не задан, `usesCleartextTraffic` не задан, атрибут `networkSecurityConfig` у тега `application` не задан. При этом в ресурсах есть `res/xml/network_security_config.xml`: `base-config cleartextTrafficPermitted="true"` и `debug-overrides` с доверием к пользовательским CA. Файл ни на что не ссылается, поэтому рабочей политикой он не является. `debug-overrides` и так действует только у отладочной сборки. При targetSdk 33 ясный текст по умолчанию запрещён. В отчёте этот XML не считается включённым cleartext.

Разрешений в манифесте 63, среди них камера, микрофон, контакты, календарь, учётные записи, телефон, геолокация медиа и установка пакетов. Для почтового клиента набор ожидаемый, но каждое опасное разрешение расширяет последствия компрометации процесса.

## 7. Декомпиляция

Чтение конкретных классов (`EmlActivity`, `DocScannerCameraActivity`, `OfflineCalendarActivity`, загрузчики библиотек) сделано по дереву JADX этого же APK: `/home/drenk83/Documents/mbks/3/YandexMail/sources`. Повторную декомпиляцию в этом прогоне сделал APKHunt: он вызвал JADX и dex2jar и записал дерево в `lab5/results/apkhunt/yandex-mail-8-81-2_SAST/`. Имя APK для APKHunt пришлось сделать `yandex-mail-8-81-2.apk`: исходное имя с пробелами и точками инструмент отвергает.

Манифест для подсчётов снят androguard-скриптом `lab5/scripts/audit_apk.py`, результат `lab5/results/manifest.txt`.

## 8. Манифест: точки входа

Сводка androguard: активностей 108, из них с `exported=true` или с intent-filter — 20. Псевдонимов активностей 7, все с фильтром. Сервисов 32, с входом снаружи 12. Приёмников 35, с входом 29. Провайдеров 20, экспортированы 3.

Главный пользовательский вход — псевдоним `ru.yandex.mail.ui.LoginActivity`. Его `targetActivity` — `com.yandex.mail.startupwizard.StartWizardActivity`. Псевдоним `LoginActivity_ny` в манифесте выключен.

Внешние данные без отдельного разрешения принимают такие компоненты.

`com.yandex.mail.eml.EmlActivity`, `exported=true`, без permission. Фильтр `ACTION_VIEW` на `content` с типами `message/rfc822` и `application/eml`, а также `file`/`content` с `pathPattern` на `.eml`. Это просмотр чужого письма, которое пользователь или другое приложение отдало через Intent.

Псевдонимы входа принимают `SEND`, `SEND_MULTIPLE` и `mailto`. Часть scheme в дампе androguard осталась ссылками ресурсов вида `@7F151000`: это не отдельные открытые scheme, а неразрешённые id.

Ссылки Passport и мессенджера: `https://passport.yandex.ru` с путями `/am/push/qrsecure` и учётными сценариями, своя scheme `ru.yandex.mail.passport`, magic-link на хосте `yx7a54f58d4ebe431caaaa53895522bf2d.oauth.yandex.ru`, `https://yandex.ru/chat` и `/messenger`, `ya.ru/m/`, scheme `messenger` и telemost. Это вход в уже задуманные сценарии входа и звонка. Без сессии они упираются в экран Passport.

Экспортированные провайдеры без полезного permission:

- `com.yandex.passport.internal.authsdk.AuthSdkProvider`, authority `com.yandex.passport.authsdk.provider.ru.yandex.mail`.
- `com.yandex.passport.internal.sso.SsoContentProvider`, authority `com.yandex.passport.internal.sso.ru.yandex.mail`. Методы `query`, `insert`, `update` и `delete` после проверки на null бросают `UnsupportedOperationException`. Утечки строк через query по коду нет. Снаружи остаётся возможность дёрнуть метод и получить исключение.
- `com.yandex.metrica.PreloadInfoContentProvider`, authority `ru.yandex.mail.appmetrica.preloadinfo.retail`. Это канал AppMetrica для preload, не почтовый ящик.

В манифесте остались тестовые компоненты `androidx.compose.ui.tooling.PreviewActivity` и `androidx.test.core.app.InstrumentationActivityInvoker$*` с `exported=true`. Это мусор сборки, а не рабочий сценарий почты.

Часть компонентов Passport закрыта разрешением `com.yandex.permission.READ_CREDENTIALS` с уровнем signature. Чужое приложение с другой подписью его не получит.

`com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity` в список экспортированных не входит. С корня adb её всё равно можно стартовать по имени компонента. Обычное стороннее приложение так сделать не может.

Сценарии, которые реально смотрелись дальше:

1. `ACTION_VIEW` на файл `.eml` внутри каталога приложения. Это источник недоверенных данных для `EmlActivity`.
2. Запуск сканера документов. Он поднимает камеру и нативную библиотеку распознавания. К письму этот путь не привязан. Он нужен, чтобы показать, какая библиотека из APK вообще загружается в этом сеансе.

## 9. Воспроизведение внешних данных

Письмо собрано локально, 240 байт:

```text
From: lab5 <lab5@example.com>
To: student <student@example.com>
Subject: lab5 external eml
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Vneshnee pismo dlya trassy Frida. Marker LAB5-EML-MARKER.
```

Файл положен в `/data/data/ru.yandex.mail/files/lab5-external.eml` от имени uid приложения `u0_a192`, режим 640. Путь внутри данных приложения выбран потому, что на API 34 чужой файл из общего хранилища сканер и просмотрщик часто не отдают по `file://`. Запуск:

```text
am start -a android.intent.action.VIEW \
  -d file:///data/data/ru.yandex.mail/files/lab5-external.eml \
  -t message/rfc822 \
  -n ru.yandex.mail/com.yandex.mail.eml.EmlActivity
```

Без Frida активность разобрала письмо и показала тему, адреса и маркер. Снимок `lab5/results/frida/screen-eml.png` снят уже под узкими хуками, вид тот же.

Код `EmlActivity.onCreate` берёт `getIntent().getData()` и открывает поток так:

```java
InputStream inputStreamOpenInputStream = getContentResolver().openInputStream(data);
```

Дальше поток разбирается, тело попадает в WebView `R.id.browser_view`. В этом классе `setJavaScriptEnabled` нет. Если `data` пустой или поток не открылся, показывается Toast и активность закрывается.

Сканер `DocScannerCameraActivity` в `onCreate` при `bundle == null` вызывает `System.loadLibrary("camera360-arcadia")` до `super.onCreate`. Снимок `lab5/results/frida/screen-scanner.png`: заголовок SCANNER, превью виртуальной камеры эмулятора, кнопки Gallery и Scans.

## 10. Трасса Frida

Сервер: `/data/local/tmp/frida-server`, бинарь `frida-server-17.4.0-android-x86_64`, после `adb root`. Скрипт `lab5/scripts/trace.js`.

Клиент `frida -l` завершается, как только закрывается stdin. Сессия держалась так: `sleep 40 | frida -U -p PID -l lab5/scripts/trace.js`. Имя процесса в `frida-ps` — `Yandex Mail`, поэтому подключение по pid, а не по имени пакета. Запуск через `frida -f` до `Java.perform` в этом приложении не доходит, использовался attach к уже живому процессу.

Подмена `System.loadLibrary` ломает создание WebView: `EmlActivity` падает с `InflateException` на `android.webkit.WebView`. Хук на все `Activity.onCreate` тоже ронял процесс на этой инфляции. В итоговой трассе хуки только на `EmlActivity.onCreate`, `DocScannerCameraActivity.onCreate` и `ContentResolver.openInputStream(Uri)`. Загрузка библиотек смотрится отдельно.

Процесс pid 9066, события из `lab5/results/frida/trace.log`:

```text
snapshot reason=at hooks-installed watched=0
activity.onCreate class=com.yandex.mail.eml.EmlActivity
  intent action=android.intent.action.VIEW type=message/rfc822
  data=file:///data/data/ru.yandex.mail/files/lab5-external.eml
  bundleNull=true
openInputStream uri=file:///data/data/ru.yandex.mail/files/lab5-external.eml
activity.onCreate class=com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity
  bundleNull=true
snapshot reason=after DocScannerCameraActivity.onCreate watched=0
snapshot reason=1.5s after DocScannerCameraActivity.onCreate watched=0
```

`openInputStream` совпал с кодом активности: внешний `file://` дочитан внутри процесса почты. Письмо при этом осталось на экране, процесс не умер.

Снимок модулей из того же долгоживущего агента библиотеку `camera360` не увидел: карта модулей агента Frida 17.4 после `android_dlopen` из APK не обновилась. Сразу после этой трассы новый attach к тому же pid 9066 (`lab5/results/frida/modules-pid9066.log`) напечатал:

```text
pid 9066
libcamera360-arcadia.so | /data/app/~~hJIM3OXk_yWCoQOCGxelTQ==/ru.yandex.mail-wnLo2YNrFJgiE-h9yCvogA==/base.apk!/lib/x86_64/libcamera360-arcadia.so
total 330
```

Библиотека отображена прямо из APK, что согласуется с `extractNativeLibs=false`. В этом сеансе не поймано ни одного входа в JNI-экспорт: хук `android_dlopen_ext` раньше ронял процесс, а `System.loadLibrary` роняет WebView. Факт загрузки `libcamera360-arcadia.so` после `onCreate` сканера с `bundle == null` есть. Вызов конкретной native-функции на кадре камеры трасса не показывает.

`libeye.so`, `libjingle_peerconnection_so.so` и `libYandexSpeechKitJni.4.15.7.so` в pid 9066 не появились. Для них нужен экран камеры эффектов, звонок или голосовой ввод после входа в аккаунт. Вход в аккаунт и вызов ключа SpeechKit не делались.

Путь письма до нативных библиотек не доходит. `EmlActivity` читает поток в Java и кладёт текст в WebView. Нативные библиотеки этого APK к разбору `.eml` не подключены.

## 11. Стоки и опасные API

Подсчёт `lab5/scripts/audit_apk.py`, файл `lab5/results/api-hits.txt`. Это число инструкций invoke, а не число подтверждённых уязвимостей.

| Вызов | Число |
|---|---|
| `System.loadLibrary` | 8 |
| `System.load` | 3 |
| `Runtime.exec` | 5 |
| `ProcessBuilder` | 1 |
| `WebView.loadUrl` | 36 |
| `WebView.loadData` | 8 |
| `addJavascriptInterface` | 25 |
| `setJavaScriptEnabled` | 21 |
| `evaluateJavascript` | 5 |
| `setAllowFileAccess` | 16 |
| `setAllowUniversalAccessFromFileURLs` | 3 |
| `shouldOverrideUrlLoading` | 5 |
| `Cipher.getInstance` | 15 |
| `MessageDigest` | 40 |
| `SecretKeySpec` | 15 |
| проверка TrustManager | 26 |
| `HostnameVerifier` | 0 |
| `SSLContext` | 14 |
| `CertificatePinner` | 9 |
| `HttpURLConnection` | 112 |
| `HttpsURLConnection` | 8 |
| `openFileOutput` | 1 |
| `getSharedPreferences` | 135 |
| `rawQuery` | 69 |
| `execSQL` | 172 |
| `ContentResolver.query` | 41 |
| `openInputStream` | 40 |
| `Intent.getData` | 77 |
| `Intent.getDataString` | 5 |
| `getStringExtra` | 120 |
| `getParcelableExtra` | 72 |
| `getClipData` | 11 |
| `sendBroadcast` | 25 |
| `startActivity` | 213 |
| `Log.d` / `Log.e` | 322 / 377 |
| `FileOutputStream` / `FileInputStream` | 86 / 81 |
| `DexClassLoader` | 0 |
| `PathClassLoader` | 1 |
| обращения к WebSettings | 141 |

Строковые `Runtime.exec`, которые попались при чтении, фиксированы: `getprop ro.build.type` и `cat /etc/os-release | grep ^ID`. Это опрос свойств устройства, а не подстановка данных из Intent.

`OfflineCalendarActivity.V3` включает JavaScript, доступ к file URL и универсальный доступ с file URL, у метода стоит `@SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})`. Рядом `webView.loadUrl(str)`. Для офлайн-календаря file URL с универсальным доступом — отдельная находка: страница из файла может читать другие file URL. Исправление: выключить `setAllowFileAccessFromFileURLs` и `setAllowUniversalAccessFromFileURLs`, грузить календарь через `https` или через `WebViewAssetLoader`.

Девять попаданий `CertificatePinner` — это класс OkHttp в составе приложения, а не доказательство, что почтовый клиент включает pinning на свои хосты.

Явные стоки для внешнего письма: `ContentResolver.openInputStream` в `EmlActivity` и дальнейшая отдача тела в WebView. Для сканера сток — `System.loadLibrary("camera360-arcadia")` и native-методы пакета `ru.yandex.dict`.

## 12. Нативные методы

Тот же скрипт androguard выписал все методы с флагом `ACC_NATIVE`. Итог в `lab5/results/natives.txt`: 339 методов.

| Префикс класса | Методов | Библиотека |
|---|---|---|
| `ru.yandex.speechkit` | 110 | `libYandexSpeechKitJni.4.15.7.so` |
| `org.webrtc` | 89 | `libjingle_peerconnection_so.so` |
| `ru.yandex.dict` | 78 | `libcamera360-arcadia.so` |
| `org.sqlite.core` | 38 | имя `sqlitejdbc`, файла `.so` в APK нет |
| `com.yandex.metrica` | 16 | `appmetrica-native-runner` и `appmetrica-service-native`, файлов `.so` в APK нет |
| `com.yandex.eye` | 8 | `libeye.so` |

Загрузка по строкам в байткоде, которые стоят рядом с `loadLibrary`: `eye` из `com.yandex.eye.nativebits.EyeNative`, `camera360-arcadia` из сканера, `jingle_peerconnection_so` из `org.webrtc`, `YandexSpeechKitJni.4.15.7` через загрузчик с запасным извлечением из zip, `sqlitejdbc`, `appmetrica-native-runner`, `appmetrica-service-native`. Число 43 в сыром `load-libraries.json` шире настоящих `loadLibrary`: в него попадают любые invoke со словом load. Строгих вызовов `loadLibrary` восемь.

`EyeNative` объявляет `setCameraYUVBuffer`, `setCameraRGBABuffer`, `processBufferBug` и `processLut`. Эти методы принимают `ByteBuffer` кадра. `processBufferBug` по имени выглядит как учебный дефект обработки буфера. В этом прогоне кадр в него не отправлялся.

## 13. Сторонние компоненты в `.so`

Смотрелись четыре библиотеки ABI x86_64 из APK, каталог `lab5/work/native/x86_64`. Сводка `lab5/results/oss-summary.txt` от 2026-10-31. Поиск строк `libpng`, `png_read` и `png_create` по всем четырём файлам дал 0 попаданий. Версии, которых нет в строках, не додумываются.

`libcamera360-arcadia.so`. ELF x86-64, Android 21, NDK r22 (7026061), stripped. Нужны `libdl`, `liblog`, `libc`, `libm`. Экспортов `Java_` 235, `JNI_OnLoad` нет. В путях сборки есть `contrib/libs/opencv` и `contrib/restricted/abseil-cpp-tstring`. Числовой версии OpenCV в строках нет. JNI-пакет `ru.yandex.dict`. Библиотека обрабатывает кадр камеры и изображение документа в сканере. Динамически она отображена в pid 9066, путь `base.apk!/lib/x86_64/libcamera360-arcadia.so`.

`libeye.so`. NDK r21e (7075529), BuildID sha1 `619564560c8fc1343932638d95409731916b1ba3`. Нужны `libandroid`, `libGLESv3`, `libjnigraphics`, `liblog`, `libm`, `libdl`, `libc`. Экспортов `Java_` восемь, `JNI_OnLoad` нет, баннера чужой библиотеки нет. Класс `EyeNative` грузит её в статическом инициализаторе. Методы принимают буферы камеры. В сеансе письма и сканера документов она не загружалась.

`libjingle_peerconnection_so.so`. NDK r20 (5594570), BuildID xxHash `d62e16edf2ed315a`. Экспортов `Java_` 170, `JNI_OnLoad` есть. Строки указывают на WebRTC (`.../home/dbrylev/webrtc/src/...`), BoringSSL (`third_party/boringssl`, `OPENSSL_internal`, CRYPTOGAMS), libyuv, libvpx (VP8/VP9), Opus, SILK, iLBC, G.722, usrsctp, protobuf и abseil. Это стек звонка: медиа и DTLS. Номера релиза BoringSSL в строках нет, называть её OpenSSL конкретной версии нельзя. В сеансе без звонка библиотека не загружалась.

`libYandexSpeechKitJni.4.15.7.so`. stripped, BuildID sha1 `7a7d54d94df078dd8c5be851ab348dc3467049be`. Экспортов `Java_` 115, `JNI_OnLoad` есть. Имя файла задаёт SpeechKit 4.15.7. В строках есть Ogg/Opus, необязательный protobuf и WebRTC VAD. Строка `libSpeechKit v` есть, числового хвоста после неё в выборке нет. Ключ передаётся в `native_init` из `com.yandex.mail.l.SPEECHKIT_API_KEY`. В декомпиляте константа `90e12258-1aa1-4f2c-904a-42f23878322e`. Запрос к API с этим ключом не отправлялся. Исправление: не класть ключ в клиент, ограничить его на сервере и отозвать тот, что уже в сборке 8.81.2.

## 14. Достижимость нативного кода от чтения данных

Источник письма — `Intent.getData` и `openInputStream` в `EmlActivity`. По коду активности вызова `loadLibrary` и native-методов нет. Трасса это подтвердила: после `openInputStream` четыре библиотеки APK в процесс не вошли.

Источник кадра сканера — `DocScannerCameraActivity.onCreate`. При пустом `bundle` первая строка метода — `System.loadLibrary("camera360-arcadia")`. Трасса записала `bundleNull=true`. Повторный attach увидел библиотеку в том же процессе. Цепочка «активность сканера загрузила libcamera360-arcadia.so из APK» собрана из кода и двух сессий Frida. Цепочка «конкретный JNI прочитал байты кадра» не собрана.

`libjingle_peerconnection_so.so` достижима из `org.webrtc` при создании peer connection. `libYandexSpeechKitJni.4.15.7.so` достижима из `BaseSpeechKit` после инициализации с ключом. `libeye.so` достижима из клинит `EyeNative`. Ни один из этих трёх путей в сеансе не выполнялся.

FlowDroid эту достижимость не дополнил: в его 18 результатах нет `EmlActivity`, `openInputStream`, `camera360`, SpeechKit и WebRTC. Подробности прогона в следующем разделе.

## 15. FlowDroid

Команда, каталог платформ `lab5/work/android-sdk/platforms`, файл источников и стоков `lab5/work/tools/flowdroid/SourcesAndSinks.txt` (460 строк, штатный набор Android, без добавления всех 339 native-методов):

```text
java -Xmx8g -cp <classpath FlowDroid 2.15.1> soot.jimple.infoflow.cmd.MainClass \
  -a "Yandex Mail_8.81.2_APKPure.apk" \
  -p lab5/work/android-sdk/platforms \
  -s SourcesAndSinks.txt \
  -o lab5/results/flowdroid/yandex-mail.xml \
  -cg CHA -ca FAST -l NONE -dt 480 -ct 120 -mt 4 -lp
```

Решатель потока занял 86 секунд, пик памяти 8512 МБ, таймаут 480 секунд не сработал. Итог инструмента: `Found 18 leaks from 36 sources`. XML — `lab5/results/flowdroid/yandex-mail.xml`.

Смысл этих 18 путей, без выдачи их за эксплуатацию:

- ответ `URLConnection.getInputStream` уходит в буфер AppMetrica, старой Метрики и загрузчика push, а также в кэш Lottie;
- `WifiInfo.getSSID` попадает в список строк аналитики;
- `Cursor.getString` из базы подсказок почты попадает в `Appendable` и в `SharedPreferences.Editor.putString`;
- курсор вложений логируется через `Log.d`;
- `File.getCanonicalFile` доходит до `File.delete` в `SharingFileProvider`;
- `PackageManager.queryIntentActivities` доходит до `Intent.setComponent` в фабрике соцвхода Passport и в `com.yandex.mail360.b`.

Это связи внутри аналитики, кэша и выбора компонента по уже известному пакету. Потока от просмотра `.eml` к нативному коду анализ не построил. Предупреждения типизации Soot на обфусцированных классах в логе есть, на число 18 они не пересчитывались вручную: в отчёт входит то, что напечатал сам FlowDroid.

## 16. OWApp и автоматический анализ

Репозиторий `Mobile-IoT-Security-Lab/OWApp-Benchmarking-Suite` клонирован 2026-10-31. Файла `download_script.py` в нём нет. Загрузка описана в `BenchmarkSuite/DownloadScript.sh` и начинается с `sudo apt-get`. Запуск инструментов — `BenchmarkSuite/RunningScript.sh <каталог apk>`. Он по очереди зовёт Trueseeing, APKHunt, `sudo docker` для SEBASTiAN и скрипт MobSF.

Локальные копии лежат в `lab5/owapp/`. `DownloadScript.sh` не ставит пакеты и не качает датасет. Он делает жёсткую ссылку на APK варианта в `lab5/owapp/apk/yandex-mail-8-81-2.apk`. Контрольная сумма после скрипта совпала с исходным файлом. `RunningScript.sh` по умолчанию смотрит этот каталог и явно пропускает SEBASTiAN и MobSF. Сам `RunningScript.sh` повторно не запускался: Trueseeing и APKHunt уже шли отдельными командами с теми же флагами, а второй проход только дублировал бы нагрузку.

### Trueseeing 2.2.11

```text
trueseeing -eqc 'as;gj! lab5/results/trueseeing/yandex-mail.json' <apk>
```

Инструмент напечатал `found 8068 issues (66.37 sec.)`. JSON группирует их в 37 записей: 26 уровня Info, 6 Medium, 5 Low. Высокого уровня нет. Пакет в JSON — `ru.yandex.mail`, версия 8.81.2, тот же SHA-256.

Записи Medium и Low по полю `instances` в JSON:

| Уровень | CVSS | Экземпляров | Сигнатура | Суть |
|---|---|---|---|---|
| Medium | 5.1 | 5 | crypto-xor | XOR не как стойкий шифр, в том числе в рекламном SDK |
| Medium | 5.1 | 1 | security-tls-interception | признак подмены проверки TLS |
| Medium | 4.2 | 1 | manifest-cleartext-permitted | cleartext в XML политики |
| Medium | 4.2 | 1 | security-cxss-jq | возможный XSS через jQuery |
| Medium | 4.2 | 11 | security-tamperable-webview | WebView, который можно подменить |
| Medium | 4.0 | 28 | crypto-static-keys | статические ключи |
| Low | 3.9 | 1 | crypto-ecb | режим ECB |
| Low | 3.7 | 1 | security-insecure-webview | смешанный контент |
| Low | 3.0 | 2 | privacy-device-id | идентификатор устройства |
| Low | 2.2 | 2 | crypto-static-keys | открытый ключ в комплекте, среди строк есть сертификат `YandexMobileRootCA` |
| Low | 2.0 | 495 | security-log | журналирование |

Флаг cleartext у Trueseeing относится к файлу `network_security_config.xml`. Androguard показывает, что приложение на этот файл не ссылается. Считать, что выпуск 8.81.2 разрешает ясный текст, по одному этому срабатыванию нельзя.

Info-записи в основном про библиотеки, отражение, URL в строках, 339 native-методов, 63 разрешения и открытые компоненты. Они совпадают с ручным разбором и нового канала атаки не добавляют.

### APKHunt

```text
apkhunt -p lab5/results/apkhunt/yandex-mail-8-81-2.apk -l
```

Старт `2026-10-31 18:48:53`, финиш `2026-10-31 19:11:08`. Инструмент напечатал `Total time taken for hunting: 22m14.841748933s`. SHA-256 в шапке совпал с APK, MD5 в шапке `e23b6fcd0bcff531a1eb10ab970c286b`. Свой JADX дошёл до `28358` единиц и закончил строкой `finished with errors, count: 267`. Текст прогона: `lab5/results/apkhunt/APKHunt_yandex-mail-8-81-2_2026-10-31_18-48-53.txt`. Дерево декомпиляции в git не кладётся.

Строки, которые APKHunt напечатал сам:

- атрибут `android:networkSecurityConfig` в манифесте не найден;
- файл `res/xml/network_security_config.xml` найден, и по нему же выставлены cleartext и custom trust anchors;
- `android:allowBackup="true"` не найден;
- `android:debuggable="true"` не найден;
- экспортированные activities, content providers, broadcast receivers и services посчитаны как 0;
- утечки в журнал: `Total file sources are: 455 & its total instances are: 1451`;
- жёстко прошитые ссылки: `Total file sources are: 250 & its total instances are: 473`.

Ноль экспортированных компонентов не сходится с манифестом, который APKHunt сам записал в дерево: у псевдонима `ru.yandex.mail.ui.LoginActivity` стоит `android:exported="true"`, и таких атрибутов в файле 43. Для поверхности атаки остаётся подсчёт androguard из раздела 8.

Дальше по тем же разделам лога, без перевода каждой строки в отдельную уязвимость. В `strings.xml` есть `firebase_database_url` со значением `https://yandex-mail.firebaseio.com`. Это строка конфигурации, правила базы инструмент не проверял. `WebView.setWebContentsDebuggingEnabled` берёт флаг `KEY_WEB_VIEW_DEBUGGING_ENABLED`, в вызове значение по умолчанию `false`. Признаки root и антиотладки лежат в AppMetrica (`RootChecker` и соседний класс Метрики), не в экране почты. Проверок целостности файлов, эмулятора и SafetyNet в логе нет. Раздел про ключи смотрит `strings.xml` и константу SpeechKit из `com.yandex.mail.l` не выписывает. Её даёт ручной разбор JADX из раздела 13.

## 17. Что стоит поправить в Yandex Mail

Правки ниже относятся к наблюдаемому поведению сборки 8.81.2. Это разбор учебного образца, а не инструкция по воздействию на боевые серверы.

1. Убрать константу SpeechKit из клиента и отозвать уже опубликованный ключ. Голосовой канал поднимать с короткоживущим токеном.
2. В `OfflineCalendarActivity` выключить доступ WebView к file URL и универсальный доступ между file URL.
3. Не экспортировать `EmlActivity` шире, чем нужно для просмотра вложения. Поток из `content://` и `file://` разбирать как данные, не как страницу с чужим скриптом. JavaScript в этом WebView не включать.
4. У тестовых активностей Compose и AndroidX выставить `exported=false` или не паковать их в release.
5. `SsoContentProvider` не должен быть доступен чужим uid, даже если методы бросают исключение. Поставить signature-permission или `exported=false`.
6. Файл `network_security_config.xml` либо удалить, либо подключить явно и убрать `cleartextTrafficPermitted`, чтобы следующий рефакторинг не включил его случайно.
7. Для `libeye` имя `processBufferBug` стоит убрать из экспортной поверхности или закрыть проверкой границ буфера на стороне Java до вызова JNI.

## 18. Выводы

mfva — учебный набор ошибок по хранению, криптографии, сети и экспортным компонентам. Самые прямые: DES/ECB с ключом `Gangnam!`, MD5, пароли `user1`/`pass1`/`pass0` и токен по HTTP, `allowBackup`, экспортированный приёмник без разрешения и WebView с JavaScript на `http://example.com`. Необъявленное `CustomPermission` часть компонентов как раз закрывает, несмотря на имена `Unprotected*`.

Yandex Mail 8.81.2 принимает внешнее письмо через экспортированную `EmlActivity`. На эмуляторе API 34 письмо с маркером `LAB5-EML-MARKER` открылось, Frida записала `openInputStream` на этот `file://`. Нативные библиотеки APK к этому пути не подключаются. Сканер документов в том же процессе загрузил `libcamera360-arcadia.so` из APK. В библиотеках лежат OpenCV без номерной версии, WebRTC с BoringSSL, libyuv, libvpx, Opus и SpeechKit 4.15.7. libpng в них нет. FlowDroid нашёл 18 потоков, в основном аналитика и курсоры, и не связал письмо с native-кодом. Trueseeing сгруппировал 8068 срабатываний в 37 записей без уровня High. APKHunt шёл 22 минуты 15 секунд. Он подтвердил отсутствие `allowBackup` и `debuggable`, снова увидел cleartext в неподключённом `network_security_config.xml` и ошибся в сводке экспортированных компонентов: напечатал 0 при живых `android:exported="true"` в том же манифесте. MobSF и SEBASTiAN на стенде не запускались.

## Источники

1. OWASP MASVS, категории v1: архитектура, хранение, криптография, аутентификация, сеть, платформа, качество кода, устойчивость. https://github.com/OWASP/owasp-masvs
2. OWASP MASTG, проверки Android к тем же категориям. https://github.com/OWASP/owasp-mastg
3. Kotlin Security Considerations (Kotlin-SCP), те же классы ошибок для кода на Kotlin. Приложение mfva на Java, правила перенесены по смыслу.
4. Исходники mfva, пакет `com.appknox.mfva`, каталог `mfva-master`.
5. APK Yandex Mail 8.81.2 из архива преподавателя, SHA-256 `6fb616ce30b13dc911a9dcdd2ddfeb3450a4eb6cbf49a99733c5aefa8680463c`.
6. Журналы прогонов: `lab5/results/manifest.txt`, `api-hits.txt`, `natives.txt`, `oss-summary.txt`, `frida/trace.log`, `frida/modules-pid9066.log`, `flowdroid/yandex-mail.xml`, `trueseeing/yandex-mail.json`, `apkhunt/APKHunt_yandex-mail-8-81-2_2026-10-31_18-48-53.txt`.
7. OWApp Benchmarking Suite, `BenchmarkSuite/DownloadScript.sh` и `RunningScript.sh`. Локальная правка: `lab5/owapp/`.
