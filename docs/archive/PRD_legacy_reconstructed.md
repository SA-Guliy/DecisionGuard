# Legacy PRD (Reconstructed from Chat)

> Source: reconstructed from prior project discussion text (not byte-identical git snapshot).

Глубокий анализ твоей концепции (The True Vision)

1. От «Анализатора A/B тестов» к «Универсальному Радару Решений»

Суть: A/B тест — это лишь один из способов принять решение. Твой продукт должен подключаться к любым инициативам. Ввели новый тариф, изменили логистику, запустили триал.

Как это работает: Платформа работает как радар. Она сканирует не только целевую метрику («ура, триалов стало больше»), но и всю периферию: качество услуг, нагрузку на саппорт, скрытые косты, инфраструктуру.

2. Накопление знаний и Отложенный эффект (Где и как мы это храним?)
важный вопрос: «где копим в векторах в json?».

Ответ: Мы используем гибридную память.

В JSON мы храним жесткие факты и структуру (дата, инициатива, какие метрики выросли сразу, какие упали через 3 месяца).

В Векторах (Vector DB) мы храним смысл и паттерны.

Как это выглядит на практике: Менеджер предлагает: «Давайте дадим скидку 50% на первый месяц». Система переводит это в вектор (смысл: агрессивный демпинг для захвата базы), ищет в базе и говорит: «Год назад мы делали подобное (кейс со скидкой 40%). Сначала всё было ок, но через 4 месяца мы поймали когортный отток, потому что пришли халявщики. Паттерн совпадает на 85%». Это накопительная мудрость бизнеса.

3. Проактивный Ко-пилот, а не Шлагбаум

Суть: Commander не должен быть просто судьей с табличкой «STOP». Бизнесу нужно расти. Если инициатива опасна, ИИ должен сказать: «Стоп, эта механика ударит по марже. НО, если мы изменим порог бесплатной доставки с $50 до $75, мы сохраним рост базы и защитим маржу».

Ценность: Мы продаем не инструмент запретов, а инструмент безопасного поиска точек роста.

4. Защита данных клиента (Проблема «Фейков»)

Суть: Ни один банк или крупный ритейл не отдаст реальные суммы выручки в API Groq или OpenAI.

Решение: Мы строим Data Sanitization & Obfuscation Layer (Слой анонимизации). Перед тем как данные уходят в облачный ИИ, наш локальный скрипт превращает $1,500,000 выручки в абстрактное «Метрика X», а рост конверсии в «относительное изменение +15%». ИИ анализирует чистую логику (ризонинг), возвращает ответ, а наша система локально расшифровывает его обратно в понятный бизнесу вид. Данные в безопасности.

5. Зачем нужен трекинг затрат (Тотальный трекинг) глазами инвестора?

Объясняю: Представь, что радар сканирует 10,000 инициатив в день. Если на каждую натравливать самую умную и дорогую модель (Commander), клиент разорится на счетах за API. Инвестору нужно доказать, что наша система экономически выгодна. Мы показываем: "Смотрите, наш глупый и дешевый агент (Captain) за $0.00003 отсеивает 80% мусора. И только 20% сложных кейсов доходят до умного Commander'а. Наша архитектура экономит ваши деньги". То есть трекинг нужен, чтобы доказать жизнеспособность продукта в масштабе.

- - - - - - - - - - - - - - - - - - - - - - - - - - 
Как теперь выглядит Архитектурный Документ (PRD)

Если ты согласна с моим анализом выше, вот как должен звучать документ, который мы отдадим аудитору. Прочти его медленно:

Раздел 1: Универсальный Радар (Business Impact Radar)
Система — это не просто валидатор тестов, а радар долгосрочных последствий. Она анализирует любые бизнес-изменения на предмет угрозы периферийным метрикам (LTV, качество услуг, постоянные расходы, инфраструктура). Главная задача — находить отложенные во времени негативные эффекты (Delayed Impact).

Раздел 2: Проактивный Ризонинг (Proactive Mitigation)
Агент Commander (принимающий решения) не ограничивается бинарными ответами (GO/STOP). При обнаружении рисков он обязан генерировать альтернативные сценарии (Mitigation Proposals) — предлагать варианты корректировки инициативы для сохранения эффективности бизнеса и предотвращения потери денег.

Раздел 3: Гибридная Накопительная Память (Cumulative Knowledge Base)
Система должна иметь механизм непрерывного обучения на истории компании. Используется гибридный подход:

JSON-хранилище для структурированной записи таймлайна экспериментов (что было на 14-й день, что вскрылось через 3 месяца).

Векторная база (In-memory RAG) для семантического поиска исторических паттернов провалов, чтобы предупреждать о скрытых граблях до старта новой инициативы.

Раздел 4: Абсолютная Безопасность Данных (Data Sovereignty)
Чтобы защитить интеллектуальную собственность клиентов от утечек в сторонние LLM-облака, внедряется слой анонимизации (Sanitization/Obfuscation). Реальные финансовые показатели и PII локально конвертируются в относительные величины (синтетические фейки/векторы) перед отправкой в API, а затем расшифровываются обратно.

Раздел 5: Рентабельность и Отказоустойчивость (Enterprise Viability)

Многоуровневая фильтрация: Наличие легковесного агента (Captain) для отсева базовых ошибок до включения дорогих reasoning-моделей. Тотальный трекинг токенов/центов доказывает инвесторам дешевизну эксплуатации системы.

Непрерывность бизнеса: Встроенный фолбек на локальные модели (Edge AI) при падении облака, с механизмом последующей асинхронной сверки (аудита) решений локальной модели с эталонной

______________________________________________________________________________________________
PRD: AI-Driven A/B Test Governance & Audit Engine
Позиционирование: False Success Insurance & Corporate Memory Graph.
Форм-фактор: B2B SaaS / Облегченный CLI-инструмент для интеграции в CI/CD пайплайны и Slack.

1. Концепция продукта (False Success Insurance & Corporate Memory Graph)
Движок представляет собой универсальную Domain-Agnostic инфраструктуру для аудита A/B тестов и страхования от ложного успеха. Система не просто оценивает текущий эксперимент, а проверяет, не повторяет ли команда исторический паттерн, который раньше приводил к скрытым убыткам. Клиент передает в ядро внешний `domain_template` с бизнес-физикой, а ядро применяет эту физику одинаково строго в любом домене.

2. Целевая аудитория и GTM-стратегия
Аудитория: Lead Data Scientists и Data Engineers в растущих стартапах, которые устали от ручного аудита кривых экспериментов продуктовых команд.

Go-to-Market (GTM): Легковесная интеграция (CLI / GitHub Action). Инструмент получает read-only доступ к агрегированным логам (Snowflake/BigQuery), прогоняет их через агентов и отправляет Decision Card (GO / STOP_ROLLOUT) напрямую в Slack или Jira команды.

3. Конкурентный ров и Бизнес-модель (Moat & Business Model)

Marketplace of Expertise: Конкурентное преимущество продукта строится не на обертке вокруг LLM, а на встраиваемой экспертизе. Технически скопировать вызов OpenAI легко. Скопировать библиотеку из сотен выверенных Data Contracts, учитывающих сложную физику ценообразования (pricing elasticity), двусторонних маркетплейсов и операционных процессов — крайне сложно. Мы продаем "Интеллект Senior-аналитика в формате JSON".

GTM: Интеграция через CLI (Command Line Interface) или GitHub Actions. Инструмент встраивается в существующий ETL пайплайн данных, забирает результаты тестов (read-only) и отправляет Decision Card прямо в рабочую среду команды (Slack/Jira).

4. Ключевой функционал: Hybrid Search Architecture (Neuro-Symbolic)
При поступлении нового A/B кейса система формирует семантический профиль гипотезы и запускает гибридный поиск в два шага:

1) Semantic Retrieval:
- По смыслу ищет похожие исторические кейсы в Vector DB (описания гипотез, выводы, риски, пост-мортемы).

2) Structured Fact Pull:
- По найденным `experiment_id` подтягивает точные цифры из Structured SoT (JSON Ledger/таблицы фактов): метрики, guardrails, статусы, исходные артефакты.

В LLM-контекст попадает только компактный `historical_context_pack` (top-k релевантных кейсов + проверенные факты), что снижает стоимость, latency и риск галлюцинаций.

5. Нефункциональные требования и Guardrails
Ограничения инфраструктуры: Жесткий лимит потребления RAM — 8 GB (эффективный max_payload_bytes настроен на безопасные 6 GB — OOM Headroom). `concurrency=1` (последовательная обработка). Очереди сверки обрабатываются через `batch_nightly` для снижения нагрузки на сервер.

Read-only SQL: SQL-инъекции предотвращаются на уровне архитектуры: запросы агентов ограничены операторами `SELECT`.

Fail-Closed Policy: При integrity-ошибках, невалидном шаблоне, нарушении observability или конфликте контекстов решение автоматически ограничивается `HOLD_NEED_DATA` или `STOP`.

6. Governance и Human-in-the-Loop
Система может выдавать только рекомендацию (`recommended_override`) и не имеет права автоматически менять финальный бизнес-вердикт. Любое изменение решения требует явного ручного аппрува с сохранением аудиторного следа.

7. Эвалюация и Критерии приемки (Evaluation & Acceptance)
Ключевые KPI привязываются к бизнес-результату, а не к формальному совпадению с экспертным вердиктом:

- `would_have_prevented_loss_rate`: доля исторических убыточных раскаток, которые система блокировала бы до релиза.
- `decision_regret_rate`: доля решений, которые были пересмотрены постфактум как неверные (по итогам фактического бизнес-эффекта).

Обязательное условие приемки: conformance-тесты по контрактам, guardrails и evidence-grounding должны проходить в fail-closed режиме.

## 8. Blueprint v2.1 (Executable Runtime)

### 8.1 Gate order (fail-closed)

Canonical SoT lives only in `src/architecture_v3.py`.

Required gate order:
`historical_retrieval_gate -> doctor -> handoff_contract_guard -> evaluator -> commander -> acceptance -> pre_publish`

Full gate sequence:
`context_frame -> historical_retrieval_gate -> doctor -> handoff_contract_guard -> anti_goodhart_sot -> evaluator -> commander -> historical_retrieval_conformance_gate -> quality_invariants -> reasoning_score_policy -> governance_ceiling -> acceptance -> pre_publish`

Rule: Doctor must not run without a valid `historical_context_pack` built in `retrieval_mode=semantic_hybrid_mvp` (`semantic retrieval + structured fact pull`, MVP runtime mode).

### 8.2 Centralized secure LLM gateway

All cloud/backend LLM access is allowed only through `src/llm_secure_gateway.py` (runtime + POC).
Policy scope: all scripts launched by `scripts/run_all.py` (runtime scope).

Direct cloud SDK/API calls in runtime scope are forbidden and treated as CRITICAL acceptance failure (`SANITIZATION_REQUIRED_FOR_CLOUD`).
Any cloud call must produce `obfuscation_map_ref` + run-scoped manifest + audit trail; missing trail is CRITICAL (`SANITIZATION_AUDIT_TRAIL_MISSING`).

### 8.3 Sanitization policy contract

Contract: `configs/contracts/sanitization_policy_v1.json`.

Required policy fields:
- `storage_policy`
- `encrypted_at_rest=true`
- `kms_key_ref`
- `ttl_hours`
- `allowed_readers`
- `key_rotation_days`
- `audit_log_required=true`

Obfuscation map lifecycle is fail-closed:
`generate -> encrypt_at_rest -> sidecar_hash -> manifest_register -> TTL_purge`.

Obfuscation maps are allowed only under `data/security/obfuscation_maps/` with `.sha256` sidecar + audit log.
Missing audit trail is CRITICAL (`SANITIZATION_AUDIT_TRAIL_MISSING`).

### 8.4 KPI split

- Online (per run, CRITICAL in acceptance):
  - `prevented_loss_proxy_rate`
  - `unsafe_rollout_block_rate`
  - `evidence_coverage_rate`
- Offline (nightly/backtest):
  - `would_have_prevented_loss_rate`
  - `decision_regret_rate`

Per-run acceptance blocks on missing online KPI and missing real KPI ledger (`KPI_LEDGER_MISSING`).
Offline KPI SLA:
- `age <= 24h`: PASS
- `24h < age <= 48h`: WARN (single-run non-blocking)
- `age > 48h`: FAIL (`KPI_OFFLINE_STALE`, blocking for nightly/release acceptance)

### 8.5 Artifact Cleanup + Batch SoT (v2.1)

Batch working contour is fail-closed for Sprint-2 POC artifacts:

- Forbidden outside golden pair:
  - `reports/**/POC_DECISION_CARD_SPRINT2.md`
  - `data/**/*_poc_sprint2.json`
  - `reports/**/*_poc_sprint2.json`
- Only allowed golden pair:
  - `reports/L1_ops/demo_golden_example/POC_DECISION_CARD_SPRINT2.md`
  - `reports/L1_ops/demo_golden_example/<run_id>_poc_sprint2.json`
  - with valid `.sha256` sidecars.
- Cleanup integrity mode defaults to strict (`--strict-integrity 1`): missing/invalid sidecar is blocking (non-zero exit).
- Batch transport policy: no stdout-ingest, only explicit `--batch-record-out` path.
- Batch transport SoT-unit: `batch_record_v2` contract (schema-validated before write).
- Consolidated report source of truth is summary-only:
  - `data/batch_eval/<batch_id>_summary.json`
  - direct dependency on staging or `data/agent_reports/*_poc_sprint2.json` is forbidden.
- Cleanup migration artifacts are mandatory:
  - `_PROJECT_TRASH/MIGRATION_MANIFEST.json`
  - `_PROJECT_TRASH/MIGRATION_MANIFEST.md`
  - `_PROJECT_TRASH/rollback.sh`

Acceptance must include CRITICAL checks for:
- cleanup in `data/**/*_poc_sprint2.json`,
- cleanup in `reports/**/*_poc_sprint2.json`,
- cleanup in `reports/**/POC_DECISION_CARD_SPRINT2.md`,
- consolidated summary-only enforcement.
