# WipeCode

Rootless-твик (Dopamine, iOS 15–16.6.1). Добавляет в «Настройки» панель, где задаётся
**второй пароль стирания**, не связанный с код-паролем устройства. Если ввести именно его —
выполняется системная «Стереть контент и настройки».

## Устройство

Две половины, потому что `Settings.app` не может стирать напрямую:

| | процесс | роль |
|---|---|---|
| `WipeCodePref` | `com.apple.Preferences` | панель, ввод пароля, HMAC, отправка запроса |
| `WipeCodeSB`   | `com.apple.springboard`  | сверка HMAC, вызов `SBDeviceErase` |

`FBSSystemService` требует entitlement `com.apple.springboard`, который есть только у
процесса SpringBoard. Связь между половинами — Darwin notification (payload не несёт) +
файлы в `/var/mobile/Library/WipeCode` (оба процесса под UID `mobile`).

Darwin notification может отправить любой процесс, поэтому авторизация — не сам факт
уведомления, а HMAC-SHA256 от введённого пароля с персистентной случайной солью.
**Открытый пароль не попадает ни на диск, ни в уведомление** — только 64-символьный дайджест.

## Сборка

```sh
export THEOS=/opt/theos
cd WipeCode
make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
```

Схема `rootless` задана в корневом `Makefile`. Получится два `.deb` — `sb` ставить первым
(от него зависит второй).

## Что происходит при нажатии «Стереть устройство»

1. Панель показывает нативное поле ввода. Клавиатура и проверка длины берутся из типа
   код-пароля, который SpringBoard публикует в `device.plist`.
2. Показывается обратный отсчёт 5 секунд с кнопкой «Отмена». Запрос не отправляется, пока
   счётчик не дошёл до нуля.
3. В `request.plist` пишется дайджест, отправляется Darwin notification.
4. SpringBoard сверяет дайджест, удаляет `request.plist` (запрос не переигрывается) и
   вызывает `SBDeviceErase`.

## Диагностика

Всё пишется в один файл:

```
/var/mobile/Library/WipeCode/probe.log
```

При первом запуске SpringBoard-половина сбрасывает туда реальные сигнатуры
`SBDeviceErase`, `FBSSystemService`, `FBSSystemServiceRequest`, `SBAuthenticationManager`
и вывод `fdesetup -h`. Это нужно, чтобы закрепить точный вызов стирания: имена ключей
в `arguments` не читаются из списка методов, а подтвердить их офлайн не удалось.

Забрать лог:

```sh
ssh -p 2222 mobile@localhost 'cat /var/mobile/Library/WipeCode/probe.log'
```

## Запасной путь (root)

Если `SBDeviceErase` на этой версии iOS недоступен из SpringBoard, есть путь через
`fdesetup` от root. Он **выключен по умолчанию** и включается двумя шагами:

```sh
# 1. разово разрешить sudo без пароля только для fdesetup
echo 'mobile ALL=(root) NOPASSWD: /usr/bin/fdesetup' \
  > /var/jb/etc/sudoers.d/vo1dek
chmod 440 /var/jb/etc/sudoers.d/vo1dek

# 2. вписать реальные аргументы (взять из probe.log, раздел fdesetup -h)
plutil -insert rootEraseArgs -json '["erase", ...]' \
  /var/mobile/Library/WipeCode/secret.plist
```

## Предупреждение

Стирание необратимо. Проверять надо на устройстве без важных данных: отличить «работает»
от «не работает» без реального стирания нельзя, а таймер отмены — единственная страховка.
