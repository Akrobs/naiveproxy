# Local Caddy candidate build

Этот pipeline собирает проверочный Caddy локально и не подключается к рабочим
серверам.

Закрепленные компоненты по умолчанию:

- Caddy `v2.11.4`;
- xcaddy `v0.4.6`;
- portable Go `1.26.5` с официальной контрольной суммой;
- Naive forwardproxy commit
  `d62c80d3dd2c706b6b87579844d2397bddd18317`.

## Запуск

Из корня проекта:

```powershell
pwsh -File .\ops\caddy-build\build-caddy-candidate.ps1
```

Артефакты появятся в `dist/caddy/v2.11.4/`:

- `caddy-linux-amd64` - кандидат для Ubuntu amd64;
- `caddy-windows-amd64.exe` - локальный верификатор той же сборки;
- `manifest.json` - версии, commit и результаты проверок;
- `SHA256SUMS.txt` - контрольные суммы;
- `caddy-modules.txt` - список модулей;
- `caddy-linux-buildinfo.txt` - Go build metadata;
- `go-modules.txt` - граф зависимостей.

## Что проверяется

1. Commit forwardproxy совпадает с закрепленным значением.
2. Сборка выполняется закрепленным portable Go, системный Go не изменяется.
3. Fork компилируется и проходит тесты с выбранной версией Caddy.
4. В бинарнике зарегистрирован `http.handlers.forward_proxy`.
5. Тестовый Caddyfile проходит `caddy validate`.
6. Linux-артефакт является ELF64 для amd64.
7. Build metadata содержит нужные Caddy и forwardproxy.
8. Build metadata содержит точный commit `klzgrad/forwardproxy` и не содержит
   временных локальных путей.
9. Для артефактов рассчитываются SHA-256.

Скрипт ничего не устанавливает в `/usr/local/bin`, не меняет Caddyfile и не
перезапускает службы. Публикация на тестовый сервер выполняется отдельным этапом
только после ручной проверки manifest и контрольных сумм.

## Локальный Naive E2E

После сборки можно проверить кандидат официальным Naive-клиентом:

```powershell
pwsh -File .\ops\caddy-build\test-naive-e2e.ps1 `
  -CaddyPath .\dist\caddy\v2.11.4\caddy-windows-amd64.exe
```

Тест временно добавляет одноразовый Caddy root только в `CurrentUser\Root`,
запускает локальные Caddy и Naive, проверяет запрос через SOCKS и согласование
padding. В блоке `finally` сертификат удаляется по точному thumbprint напрямую
из хранилища текущего пользователя. Рабочие серверы в тесте не участвуют.
