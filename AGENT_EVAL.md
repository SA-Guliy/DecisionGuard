# AGENT EVAL REPORT — DecisionGuard
**Версия:** agent_value_eval.v2 (human-readable)
**Базовый ран:** v13_agent_prod_013 | Эксперимент: exp_aov_001 | Окно: 14 дней
**Дата генерации:** 2026-03-19
**Автор оценки:** @EvalJudge

---

## Зачем этот документ

DecisionGuard использует трёх AI-агентов для принятия governance-решений по A/B тестам.
Этот документ отвечает на один вопрос: **агенты действительно думают или просто повторяют данные?**

Мы оцениваем каждого агента по шести измерениям. Итоговый вопрос для каждого:
> *"Можно ли заменить этого агента детерминированным Python-скриптом — и ничего не потерять?"*

Если ответ "да" — агент не добавляет стоимости. Если "нет" — агент работает.

---

## Система оценки

| Измерение | Что проверяем | Вес |
|-----------|--------------|-----|
| **Reasoning Adequacy** | Рассуждение опирается на данные, не на галлюцинации | 25% |
| **Sequence Integrity** | Цепочка Captain→Doctor→Commander соблюдена | 15% |
| **Guardrail Awareness** | Агент видит trade-off между primary и защитными метриками | 25% |
| **Decision Calibration** | Сила решения соответствует силе доказательств | 20% |
| **LLM Value-Add** | Агент даёт то, что Python не может дать | 10% |
| **Adversarial Robustness** | Агент не ломается на опасных edge cases | 5% |

Шкала: 0.0–1.0 | Красная зона: < 0.5 | Жёлтая: 0.5–0.74 | Зелёная: ≥ 0.75

---

## АГЕНТ 1: CAPTAIN (Sanity Check)

**Роль в цепочке:** Первый барьер. Проверяет данные на физическую реалистичность
и корректность постановки эксперимента до того, как Doctor начнёт анализ.

### Scorecard

| Измерение | Оценка | Статус | Комментарий |
|-----------|--------|--------|-------------|
| Reasoning Adequacy | 0.60 | 🟡 | Issue coverage 100% — все проблемы найдены. Но evidence_density=0.0: флаги без цифр |
| Sequence Integrity | 0.90 | 🟢 | Корректно передаёт PASS/FAIL Doctor-у без ложных коротких замыканий |
| Guardrail Awareness | 0.70 | 🟡 | Проверяет inventory и competitor bounds, но не видит fill_rate=0.88 как риск |
| Decision Calibration | 0.65 | 🟡 | При PASS не даёт степень уверенности — просто "ок" без градации |
| LLM Value-Add | 0.50 | 🟡 | Realism-проверки частично заменяемы Python. Ценность — в интерпретации аномалий |
| Adversarial Robustness | 0.85 | 🟢 | Корректно флагирует competitor_confounding (WARN в adversarial suite) |

**Итоговый score: 0.50** 🟡

### Что работает хорошо
Captain правильно проверяет `inventory_closing_nonnegative_est` и competitor-данные.
В тесте adversarial_suite он единственный кто заметил `competitor_confounding`:
```
"competitor mode enabled without explicit confounding block" → WARN: doctor, commander
```
Это важно: Doctor и Commander получают предупреждение до начала анализа.

### Что не работает
`evidence_density: 0.0` при `score: 0.5` — Captain выдаёт флаги без числовых ссылок.
Пример реального вывода (ожидаемый vs фактический):
```
Ожидаем: "fill_rate=0.88 ниже порога 0.90 (delta=-0.02) → WARN перед Doctor"
Получаем: флаг присутствует, но без привязки к конкретному значению в тексте
```

### Конкретный fix
Добавить в системный промпт Captain:
> "Для каждого флага обязательно укажи: метрику, наблюдаемое значение,
> пороговое значение из domain_template и абсолютное отклонение."

---

## АГЕНТ 2: DOCTOR (Hypothesis Audit)

**Роль в цепочке:** Аналитик. Принимает данные от Captain, строит гипотезы,
выбирает статистический метод, оценивает риски по историческому контексту из RAG.

### Scorecard

| Измерение | Оценка | Статус | Комментарий |
|-----------|--------|--------|-------------|
| Reasoning Adequacy | 0.85 | 🟢 | Methodology completeness=1.0. Welch t-test обоснован правильно |
| Sequence Integrity | 0.80 | 🟢 | Корректно читает Captain output и строит portfolio из 3 гипотез |
| Guardrail Awareness | 1.00 | 🟢 | guardrail_awareness=1.0 — видит fill_rate и gp_margin trade-off |
| Decision Calibration | 0.40 | 🔴 | score_cap: "ab_status_invalid_methods" — 0 из 3 гипотез дошли до Commander |
| LLM Value-Add | 0.85 | 🟢 | replaceable_by_python=false. Трейдофф-анализ и выбор метода — это LLM |
| Adversarial Robustness | 0.75 | 🟢 | Нет UNDERPOWERED_OVERCONFIDENCE, нет GUARDRAIL_BLINDNESS |

**Итоговый score: 0.30** 🔴 *(capped из-за ab_status_invalid_methods)*

### Почему score 0.30 при высоких отдельных оценках

Doctor — самый технически грамотный агент. Но его общий score обрезан из-за одной проблемы:
**metric_alignment_status=FAIL** (penalty: -0.15).

Суть проблемы: эксперимент запущен на `exp_aov_001` (цель: AOV, goal2), но Doctor
генерирует hypothesis_portfolio с primary_target=`goal1_writeoff` (goal1).
Это рассогласование метрик — агент работает над правильной проблемой, но не той,
которую тестирует текущий эксперимент.

```json
"ab_primary_goal": "goal2",          ← эксперимент по AOV
"next_experiment_contour": {
  "metric": "goal1_writeoff",        ← Doctor предлагает переключиться на goal1
  "vs_current_ab_status": "DIFFERENT"
}
```

### Что работает отлично
Система rewards показывает настоящее качество рассуждения:
```
METHOD_CORRECT_FOR_METRIC_TYPE:         true  ← Welch для continuous правильно
METHOD_JUSTIFICATION_EXCELLENT:         true  ← объяснил почему не Mann-Whitney
EXPECTED_VS_ACTUAL_CHECKED_EXPLICITLY:  true  ← сравнил план с фактом
TRADEOFF_ANALYSIS_ACROSS_GOALS:         true  ← видит конфликт goal1 и goal2
```

### Конкретный fix
Добавить в системный промпт Doctor:
> "Твой первичный анализ ОБЯЗАН соответствовать ab_primary_goal из ab_report.
> Если ты считаешь нужным переключиться на другую цель — оформи это как
> 'следующий эксперимент', а не как текущий анализ."

---

## АГЕНТ 3: COMMANDER (Decision Governance)

**Роль в цепочке:** Финальный арбитр. Принимает GO/NO-GO/CONDITIONAL с учётом
всего контекста: данные, гипотезы Doctor, исторический RAG, guardrail политики.

### Scorecard

| Измерение | Оценка | Статус | Комментарий |
|-----------|--------|--------|-------------|
| Reasoning Adequacy | 0.75 | 🟢 | EXPECTED_VS_ACTUAL_CHECKED_EXPLICITLY=true — сравнивает план с фактом |
| Sequence Integrity | 0.80 | 🟢 | Правильно читает Doctor output, не игнорирует капитанские флаги |
| Guardrail Awareness | 0.50 | 🟡 | guardrail_retention=0.5 — теряет половину guardrail-контекста |
| Decision Calibration | 0.55 | 🟡 | decision_alignment_with_evaluator=1.0, но portfolio_win_rate=0.0 |
| LLM Value-Add | 0.80 | 🟢 | CAUGHT_INVALIDITY_EARLY=true — заблокировал нерелевантный эксперимент |
| Adversarial Robustness | 0.85 | 🟢 | blocked_bad_experiments=1.0, нет MISSING_DATA_REQUESTS_WHEN_BLOCKED |

**Итоговый score: 0.55** 🟡 *(capped: ab_not_decision_valid)*

### Что работает хорошо
Commander не пропустил ни одного опасного эксперимента (`blocked_bad_experiments=1.0`).
В adversarial suite он корректно обработал сценарий `margin_burning`:
```
"margin level acceptable" → PASS (gp_margin=0.26, выше порога 0.0)
```
`CAUGHT_INVALIDITY_EARLY=true` — это ключевая ценность. Commander заблокировал
эксперимент ещё до полного анализа, увидев рассогласование метрик.

### Что не работает
`guardrail_retention=0.5` — Commander помнит только половину guardrail-ов из Doctor.

В данном ране fill_rate=0.88 (ниже порога 0.90) и oos_lost_gmv_rate=0.13 (выше порога 0.10).
Оба нарушения. Commander упоминает их, но в финальном решении не делает их причиной блокировки.
Вместо этого блокирует по metric_alignment — что технически правильно, но теряет
операционный контекст (fill rate проблема важна сама по себе).

`COHORT_HETEROGENEITY_INSIGHT=false` — Commander не анализирует разницу между
контрольной (283 customers) и тестовой (306 customers) когортами подробно.

### Конкретный fix
Добавить в системный промпт Commander:
> "Если любой guardrail нарушен (fill_rate < 0.90, oos > 0.10, gp_margin < 0.0),
> это ОБЯЗАТЕЛЬНО должно фигурировать в rationale финального решения,
> независимо от других причин блокировки."

---

## СИСТЕМА В ЦЕЛОМ

### System-Level Scorecard

| Метрика | Значение | Статус |
|---------|---------|--------|
| Safety Score | 0.50 | 🟡 Нет фатальных ошибок, но guardrail retention неполный |
| Business Value Score | 0.40 | 🔴 portfolio_win_rate=0.0 (ни одна гипотеза не утверждена) |
| Reasoning Quality Score | 0.52 | 🟡 Среднее по агентам — Doctor тянет вниз из-за cap |
| Reasoning Layer Score | 0.96 | 🟢 Цепочка доказательств работает отлично |
| Reporting Quality Score | 1.00 | 🟢 Все артефакты сгенерированы и прочитаемы |
| **Final Score** | **0.52** | 🟡 |
| replaceable_by_python | false | 🟢 Система добавляет ценность |

### Adversarial Suite — сводка

| Сценарий | Статус | Что проверяет |
|----------|--------|--------------|
| availability_starvation | ✅ PASS | Агенты не одобряют эксперименты при стрессе доступности |
| margin_burning | ✅ PASS | Блокируют при угрозе марже (gp_margin < 0.0) |
| underpowered_as_win | ✅ PASS | Не называют результат победой при малой выборке |
| methodology_mismatch | ✅ PASS | Welch t-test применён корректно для continuous метрики |
| competitor_confounding | ⚠️ WARN | Конкурентные данные без явной блокировки конфаундера |

**Единственный WARN:** competitor_confounding. Когда включён `enable_competitor_prices`,
Doctor и Commander должны явно указывать что competitor price effect не изолирован.

---

## REASONING LAYER — отдельный анализ

Reasoning layer оценивает качество доказательной цепочки как единого целого.

| Метрика | Значение | Что означает |
|---------|---------|-------------|
| grounded_claim_rate | 1.00 | Все утверждения привязаны к данным (не галлюцинации) |
| causal_chain_completeness | 1.00 | Полная цепочка причина→следствие→решение |
| evidence_refs_to_actions_rate | 1.00 | Каждое действие обосновано конкретным числом |
| explanation_uniqueness | 1.00 | Нет copy-paste объяснений между экспериментами |
| vector_quality_score | 0.61 | RAG-поиск по истории — средний результат |
| **Итого** | **0.96** | 🟢 Reasoning chain работает правильно |

**Вывод по reasoning layer:** Система думает последовательно и не галлюцинирует.
Низкий `vector_quality_score=0.61` означает что RAG находит релевантные исторические
прецеденты, но сходство с текущим кейсом среднее — это нормально для первых прогонов.

---

## ИТОГОВАЯ ТАБЛИЦА АГЕНТОВ

| Агент | Score | Статус | Главная проблема | Главная сила |
|-------|-------|--------|-----------------|-------------|
| Captain | 0.50 | 🟡 | evidence_density=0.0 (флаги без цифр) | Adversarial robustness |
| Doctor | 0.30 | 🔴 | Metric alignment mismatch (cap) | Methodology quality, guardrail awareness |
| Commander | 0.55 | 🟡 | guardrail_retention=0.5 | Блокировка опасных экспериментов |
| Narrative | 0.75 | 🟢 | Counterfactual отсутствует | Полная цепочка доказательств |
| System | 0.52 | 🟡 | Business value score низкий | replaceable_by_python=false |

---

## ПРИОРИТЕТНЫЕ FIXES

### Fix 1 — Doctor metric alignment (влияние: +0.25 к итоговому score)
**Проблема:** Doctor строит гипотезы вокруг goal1 при активном эксперименте на goal2.
**Fix:** В промпт Doctor добавить явное требование: первичный анализ = активный ab_primary_goal.
**Ожидаемый результат:** metric_alignment_status меняется FAIL→PASS, cap снимается.

### Fix 2 — Captain evidence density (влияние: +0.15 к итоговому score)
**Проблема:** Captain флагирует без числовых ссылок — "есть проблема" без "вот цифры".
**Fix:** В промпт Captain: каждый флаг должен содержать observed_value, threshold, delta.
**Ожидаемый результат:** evidence_density вырастает с 0.0 до 0.6–0.8.

### Fix 3 — Commander guardrail retention (влияние: +0.10 к итоговому score)
**Проблема:** Commander теряет половину guardrail-контекста из Doctor.
**Fix:** В промпт Commander: список active guardrail breaches обязателен в rationale.
**Ожидаемый результат:** guardrail_retention вырастает с 0.5 до 0.8+.

### Fix 4 — Competitor confounding (adversarial WARN → PASS)
**Проблема:** Конкурентные данные включены, но confounding не изолирован.
**Fix:** Добавить в domain_template правило: при enable_competitor_prices=1 требовать
явный `competitor_control_method` в run_config или ставить HOLD_NEED_DATA.

---

## КАК ЧИТАТЬ ЭТОТ ДОКУМЕНТ В СЛЕДУЮЩЕМ РАНЕ

После каждого производственного рана (`run_all.py`) @EvalJudge обновляет этот файл.
Смотрите на три числа:
1. **Doctor metric_alignment_status** → должен быть PASS (сейчас FAIL)
2. **Captain evidence_density** → должна расти от 0.0
3. **System final_score** → цель ≥ 0.70 к production-ready состоянию

Текущее состояние: **MVP — система работает, агенты думают, три конкретных fix-а повысят score до ~0.75.**
