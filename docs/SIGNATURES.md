# Формат базы сигнатур

Файл: `onlyunlocker/data/signatures.json` (встроенная база) или
`<каталог данных>/signatures.json` (пользовательская, приоритетнее встроенной).

```json
{
  "version": "2026.10.23",
  "hashes":   [ ... ],
  "patterns": [ ... ],
  "rules":    [ ... ]
}
```

`version` — произвольная строка, показывается в интерфейсе. Валидация при обновлении:
обязательное поле `version`, массивы `hashes`/`patterns`/`rules`, хотя бы одно правило.

---

## 1. Хеш-сигнатуры (`hashes`)

```json
{
  "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "name": "EICAR-Test-File",
  "family": "Test",
  "severity": "high"
}
```

- `sha256` — 64 hex-символа, иначе запись игнорируется.
- Совпадение хеша сразу даёт вердикт **угроза** независимо от суммы баллов.
- `severity`: `low` | `medium` | `high` | `critical`.

---

## 2. Байтовые шаблоны (`patterns`)

```json
{
  "name": "Backdoor.Metasploit.Stage",
  "hex": "6d 65 74 65 72 70 72 65 74 65 72",
  "scope": "all",
  "max_scan": 4194304,
  "severity": "high",
  "family": "Backdoor"
}
```

Синтаксис `hex`:

| Запись | Значение |
|---|---|
| `4D 5A` | точные байты |
| `??` или `?` | ровно один любой байт |
| `*16` | от 0 до 16 любых байт (по умолчанию 32, максимум 4096) |

- `scope`: `head` (по умолчанию, только первые `max_scan` байт) или `all`.
- `max_scan`: сколько байт отдавать шаблону, по умолчанию 1 МБ.
- Совпадение шаблона тоже даёт вердикт **угроза**.

---

## 3. Текстовые правила (`rules`)

```json
{
  "name": "Script.PowerShell.AmsiBypass",
  "title": "Обход AMSI / отключение защиты",
  "description": "Скрипт пытается отключить AMSI или Defender.",
  "regex": "(?:amsiutils|amsiscanbuffer|set-mppreference[^\\n]{0,80}disable)",
  "extensions": [".ps1", ".bat", ".cmd"],
  "severity": "critical",
  "family": "DefenseEvasion"
}
```

- `regex` — регулярное выражение Python. Флаги задаются строкой `flags`
  (по умолчанию `"ims"`: игнорировать регистр, многострочный режим, точка = перевод строки).
  Осторожно с `[\\s\\S]` для «через несколько строк» — это надёжнее ленивых квантификаторов.
- `extensions` — где применять правило (по расширению файла). Пустой список = проверять
  любой текстовый файл. Правила применяются только к тексту (не к бинарникам).
- Пишите регулярки с ограничением длины `{0,200}`, чтобы не было катастрофического бэктрекинга.

---

## Веса и пороги

| severity | балл |
|---|---|
| `low` | 10 |
| `medium` | 25 |
| `high` | 45 |
| `critical` | 80 |

Порог «подозрительно» — 30 баллов, «угроза» — 70. Дополнительно вердикт «угроза»
выставляется при любом совпадении хеша/шаблона или срабатывании `critical`-правила.

---

## Как добавить правило

1. Откройте JSON, добавьте объект в нужный массив.
2. Проверьте базу: `python run.py info` (покажет количество правил).
3. Проверьте срабатывание: `python run.py scan путь_к_образцу --json`.
4. Прогоните тесты: `python -m pytest tests -q`.

Правило можно проверить и напрямую:

```python
from onlyunlocker.core.signatures import SignatureDatabase
db = SignatureDatabase.load()
rule = next(r for r in db.rules if r.name == "Script.Cmd.Del.ShadowCopy")
print(bool(rule.regex.search("vssadmin delete shadows /all /quiet")))
```
