# Report: прямые ссылки на скачивание CA (для CI/автоматизаций)

- **Дата:** 2026-10-06
- **Профиль:** investigation + ui-improvement
- **Статус:** Done

## Задача

Проверить матрицу доступа к скачиванию CA: в UI скачивание идёт кнопкой
(axios → blob → синтетический `<a download>`), а для CI-автоматизаций нужны
прямые ссылки без авторизации — ЦА считаются открытыми материалами.

## Результат проверки

**Бэкенд уже отдаёт всё публично.** Авторизация в VaulTLS — пер-хендлерные
Rocket-гарды; у всех эндпоинтов скачивания CA гард в сигнатуре отсутствует,
глобального auth-fairing нет. Blob-механика — только UI-обёртка ради имени
файла из `Content-Disposition` и JSON-ошибок, на доступность прямых ссылок
она не влияет. Менять матрицу не потребовалось.

| Что | Прямая ссылка | Авторизация |
|---|---|---|
| Сертификат CA по id (TLS: PEM по умолчанию, DER) | `GET /api/certificates/ca/<id>/download[?format=der]` | не нужна |
| Полная цепочка TLS CA (PEM) | `GET /api/certificates/ca/<id>/fullchain` | не нужна |
| CRL TLS CA (DER/PEM) | `GET /api/certificates/ca/<id>/crl?format=der\|pem` | не нужна |
| Публичный ключ SSH CA | `GET /api/certificates/ca/<id>/download` | не нужна |
| KRL SSH CA | `GET /api/certificates/ca/<id>/crl` | не нужна |
| Текущий TLS CA | `GET /api/certificates/ca/download` | не нужна |
| Бандл всех TLS CA (PEM) | `GET /api/certificates/ca/bundle` | не нужна |
| Текущий SSH CA | `GET /api/certificates/ca/ssh/download` | не нужна |

Пример для CI:

```bash
curl -fsSLo ca.crt "https://<vaultls>/api/certificates/ca/1/download"
curl -fsSLo ca-bundle.crt "https://<vaultls>/api/certificates/ca/bundle"
```

## Решение (UI)

Чтобы ссылки не приходилось собирать руками, в меню «⋮» строки CA добавлены
пункты «копировать прямую ссылку» с тостом-подтверждением:

- TLS CA: сертификат (PEM), сертификат (DER), полная цепочка (PEM), а при
  наличии ключа — CRL (DER) и CRL (PEM);
- SSH CA: публичный ключ, а при наличии ключа — KRL;
- пункт меню «⋮» теперь доступен для всех CA (раньше — только с приватным
  ключом, т.к. в меню были лишь CRL/KRL).

Копирование: `navigator.clipboard` в secure context, fallback на
`execCommand('copy')` для http-деплоев без TLS. Ссылки строятся от
`window.location.origin` — того же origin, с которым ходит `ApiClient`
(`/api` проксируется на бэкенд).

## Изменённые файлы

| Файл | Что |
|---|---|
| `frontend/src/components/CATab.vue` | меню `getCaMenuItems` с пунктами копирования ссылок, `copyToClipboard` с fallback, тосты |
| `frontend/src/locales/en.json`, `es.json` | ключи `ca.copyLink*`, `ca.linkCopied`, `ca.copyFailed` |

## Validation

- frontend: `vue-tsc` + `vite build` — зелёные; vitest 36/36
- Публичность эндпоинтов подтверждена кодом (отсутствие гардов в
  `backend/src/api.rs`, глобального auth-fairing нет) и задокументирована
  ранее в `docs/superpowers/specs/2026-07-30-agent-ca-trust-design.md`
  (Go-агент уже потребляет `ca/bundle` без авторизации)

## Ограничения (зафиксировано осознанно)

1. Матрица не менялась: скачивание CA, CRL/KRL и бандла остаётся публичным —
   это осознанный дизайн (открытые материалы, доверие распространяется
   другими механизмами). Приватные ключи CA и управление — по-прежнему
   только локальный админ.
2. Кнопка основного скачивания в UI осталась blob-механикой (имя файла из
   `Content-Disposition`, JSON-ошибки) — прямые ссылки добавлены как
   копируемые пункты меню, а не замена.
