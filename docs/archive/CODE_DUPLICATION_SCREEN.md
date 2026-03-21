# Code Duplication Screen (Living)

Короткий скрининг дублей и раздутости кода.
Цель: фиксировать, что именно дублируется, что уже убрали, что еще нужно чистить.

## Focus (current cycle)

- `scripts/run_all.py`
- отчеты прозрачности (`AGENT_REASONING_TRACE`, `AGENT_INTERACTION_FRICTION_REPORT`)
- общие SSOT-модули (`model_policy`, `status_taxonomy`, `agent_llm_auth`, `paths`)

## What Was Duplicated

### 1) LLM authenticity logic duplicated in 3 places

До чистки почти одинаковая логика жила в:
- `scripts/run_all.py`
- `scripts/build_agent_reasoning_trace.py`
- `scripts/build_agent_interaction_friction_report.py`

Что дублировалось:
- `LLM Path Reached`
- `Core LLM Accepted`
- fallback detection
- Doctor methodology provenance checks

Что сделали:
- вынесли в `src/agent_llm_auth.py`
- три скрипта теперь импортируют общую логику

Почему это важно:
- меньше расхождений между оркестратором и отчетами
- одинаковая интерпретация “реальный LLM vs fallback”

### 2) Goal/metric mapping and status sets duplicated

До чистки логика была размазана по нескольким скриптам отчетов/агентов.

Что сделали:
- SSOT в `src/status_taxonomy.py`
- подключили в `Commander`, `AB report`, `build_reports`, `trace`, `friction`

### 3) Artifact path strings duplicated

До чистки:
- много path-хардкода в разных скриптах

Что сделали:
- общие пути вынесли в `src/paths.py`
- финальный вывод `run_all` вынесли в `src/run_output_paths.py` + `src/run_summary.py`

Важно:
- `src/paths.py` сначала стал слишком большим (ухудшение)
- затем разделен обратно: общий `paths` + отдельный `run_output_paths`

## run_all.py: Readability Optimization (current result)

### Что было плохо

- длинные повторы вида:
  - `cmd = [...]`
  - `try: _run_step(...)`
  - `except SystemExit: WARN`
- много одинаковых `["python3", "scripts/...", "--run-id", ...]`
- длинный хвост отчетных шагов мешал видеть core path

### Что сделали

- добавили `_try_run_step(...)` для optional/warn pattern
- добавили `_py(...)` для компактной сборки команд
- вынесли финальный summary в `src/run_summary.py`
- вынесли path-хвост summary в `src/run_output_paths.py`

### Измеримый результат

- `scripts/run_all.py`
  - было: `934` строк (до цикла рефакторов)
  - затем: `768`
  - затем: `714`
  - сейчас: `629`

## What Still Looks Duplicated / Bloated (next targets)

### A) `run_all.py` still mixes two roles

- `core proof path` (simulation -> DQ -> AB -> 3 agents -> core checks)
- `optional/reporting tail` (много отчетов/evals/refresh)

Следующий шаг:
- явно разделить на две функции:
  - `_run_core_proof_path(...)`
  - `_run_optional_reporting_tail(...)`

### B) Many script commands are still listed inline

Даже после `_py(...)` список шагов длинный.

Следующий шаг:
- data-driven step specs для tail (короткий список конфигураций + loop)
- без потери читаемости и с явными `enabled` conditions

### C) Large script entrypoints still own too much logic

Примеры:
- `scripts/run_all.py`
- `scripts/run_commander_priority.py`
- `scripts/run_doctor_variance.py`

Направление:
- сохранять `scripts/*` как thin CLI/orchestration layer
- общую логику переносить в `src/*` (осторожно, без “разноса по 100 файлов”)

## Safety / Transparency Check (this refactor cycle)

Что не ухудшили:
- DB write не добавлялись
- remote LLM still opt-in
- fallback/provenance не скрывались
- security gates не снимались

Что улучшили:
- одинаковая логика аутентичности LLM в оркестраторе и отчетах
- выше прозрачность доказательной базы (`trace`, `friction`)

## Notes

- Это живой документ.
- Добавлять сюда только реальные дубли/раздутость, а не любые “неидеальные” места.
