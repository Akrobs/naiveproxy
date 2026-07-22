# Миграция proxy credentials в Yurich Panel 5.7

Начиная с версии `5.7.0`, открытые proxy-пароли больше не являются основным хранилищем:

- `users.conf` содержит bcrypt, совместимый со стандартным `basic_auth` Caddy;
- Hysteria 2 проверяет тот же bcrypt через локальный root-only helper;
- исходный client secret шифруется RSA-OAEP-SHA256 и нужен только для генерации клиентских URI;
- новые пользователи сразу создаются в новом формате;
- старые plaintext-записи читаются до явной миграции, поэтому обновление скрипта не обрывает клиентов.

## Перед началом

Сделай snapshot VPS у провайдера и encrypted backup:

```bash
sudo bash yurich-panel.sh credentials-status
sudo bash yurich-panel.sh backup
```

Сохрани путь к созданному `.tar.gz.enc` и пароль от него отдельно. Не используй обычный `export` как единственную внешнюю резервную копию: export содержит ключ credential vault.

## Миграция одной ноды

```bash
sudo bash yurich-panel.sh credentials-migrate
sudo bash yurich-panel.sh credentials-status
sudo bash yurich-panel.sh security-audit
sudo bash yurich-panel.sh safe-apply
sudo bash yurich-panel.sh hysteria-sync
sudo bash yurich-panel.sh protocol-validate
sudo bash yurich-panel.sh protocol-benchmark ivan 3
```

`credentials-migrate` выполняет транзакцию: создаёт bcrypt и encrypted secret, пересобирает Caddy/Hysteria и запускает post-migration audit. При ошибке user store и runtime-конфиги автоматически восстанавливаются.

## Мультисервер

Сначала мигрируй master, затем одну тестовую node:

```bash
sudo bash yurich-panel.sh nodes-sync NODE_NAME
sudo bash yurich-panel.sh nodes-test NODE_NAME
sudo bash yurich-panel.sh protocol-benchmark ivan 3
```

После успешного теста:

```bash
sudo bash yurich-panel.sh nodes-sync all
sudo bash yurich-panel.sh nodes-subscriptions
```

## Проверка файлов

Команды не показывают ни хеши, ни пароли:

```bash
sudo stat -c '%U:%G %a %n' \
  /etc/naiveproxy/users.conf \
  /etc/naiveproxy/credentials/private.pem \
  /etc/naiveproxy/credentials/users.secrets

sudo bash yurich-panel.sh credentials-status
```

Ожидаемые права для закрытых файлов: `root:root 600`, для каталога credentials: `700`.

## Rollback

Внутри `credentials-migrate` rollback автоматический. Если проблема обнаружена позднее:

1. Останови изменение пользователей.
2. Восстанови snapshot VPS или encrypted backup целиком.
3. Запусти `safe-apply`, `hysteria-sync`, `protocol-validate`.
4. Проверь существующую подписку на одном устройстве.

Не восстанавливай только `users.conf`: bcrypt store, RSA keypair и `users.secrets` являются единым состоянием.

## Граница безопасности

Client URI обязан содержать секрет, иначе приложение не сможет подключиться. Поэтому сгенерированные `links.txt`, JSON/QR и URL страницы подписки остаются bearer-секретами. Хеширование серверного store не отменяет необходимость ротировать пароль и subscription token после утечки клиентской ссылки.
