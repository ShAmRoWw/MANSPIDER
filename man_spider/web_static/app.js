"use strict";

(() => {
  // Fragments are not used for navigation. Clear stale links without parsing them.
  function clearFragment() {
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
  }
  clearFragment();

  const byId = (id) => document.getElementById(id);
  const messages = {
    "title": [
      "MANSPIDER — scan results",
      "MANSPIDER — результаты сканирования"
    ],
    "appSubtitle": [
      "Local results workspace",
      "Локальный просмотрщик результатов"
    ],
    "preferences": [
      "Display preferences",
      "Настройки отображения"
    ],
    "language": [
      "Language",
      "Язык"
    ],
    "theme": [
      "Appearance",
      "Тема"
    ],
    "themeSystem": [
      "System",
      "Системная"
    ],
    "themeLight": [
      "Light",
      "Светлая"
    ],
    "themeDark": [
      "Dark",
      "Тёмная"
    ],
    "privacyNote": [
      "Local results; no connections to scanned servers. No authentication: local users and processes have access.",
      "Локальные результаты, без подключения к сканируемым серверам. Без авторизации: доступны локальным пользователям и процессам."
    ],
    "selectScan": [
      "Select a scan",
      "Выбор сканирования"
    ],
    "workspace": [
      "Workspace",
      "Рабочее пространство"
    ],
    "scanHistory": [
      "Scan history",
      "История сканирований"
    ],
    "scan": [
      "Scan",
      "Сканирование"
    ],
    "reloadScans": [
      "Refresh list",
      "Обновить список"
    ],
    "loading": [
      "Loading…",
      "Загрузка…"
    ],
    "localAndReadOnly": [
      "Local and read-only",
      "Локально, только чтение"
    ],
    "sidebarNote": [
      "Your filters change the view, never the scan. All recorded findings remain available.",
      "Фильтры меняют выдачу, а не сканирование. Все сохранённые находки остаются доступны."
    ],
    "overview": [
      "Overview",
      "Обзор"
    ],
    "contentCoverage": [
      "Content analysis",
      "Анализ содержимого"
    ],
    "recordedFiles": [
      "Enumerated files only",
      "Только перечисленные файлы"
    ],
    "analysisCaveat": [
      "Analysis is relative to the active rules and limits, not proof that every byte or embedded object was checked. Files inside inaccessible directories cannot be counted.",
      "Анализ оценивается относительно активных правил и лимитов: это не означает проверку каждого байта или вложенного объекта. Число файлов внутри недоступных каталогов неизвестно."
    ],
    "analysisLegacy": [
      "This session has no recorded content-analysis counters. Processed files are not assumed to have had their content analyzed.",
      "В этой сессии нет сохранённых счётчиков анализа содержимого. Статус «Обработано» не считается подтверждением анализа содержимого."
    ],
    "resultsSection": [
      "Results section",
      "Раздел результатов"
    ],
    "findings": [
      "Findings",
      "Находки"
    ],
    "coverage": [
      "Coverage & issues",
      "Покрытие и проблемы"
    ],
    "refineResults": [
      "Refine results",
      "Настроить выдачу"
    ],
    "filtersHint": [
      "Filters and saved views",
      "Фильтры и сохранённые наборы"
    ],
    "rule": [
      "Rule",
      "Правило"
    ],
    "severity": [
      "Severity",
      "Критичность"
    ],
    "confidence": [
      "Confidence",
      "Уверенность"
    ],
    "reviewStatus": [
      "Manual review",
      "Ручная проверка"
    ],
    "reviewAll": [
      "All findings",
      "Все находки"
    ],
    "reviewUnreviewed": [
      "Only unreviewed",
      "Только непроверенные"
    ],
    "reviewReviewed": [
      "Only reviewed",
      "Только проверенные"
    ],
    "reviewed": [
      "Reviewed",
      "Проверено вручную"
    ],
    "unreviewed": [
      "Not reviewed",
      "Не проверено вручную"
    ],
    "markReviewed": [
      "Mark reviewed",
      "Пометить проверенным"
    ],
    "markUnreviewed": [
      "Mark unreviewed",
      "Снять отметку проверки"
    ],
    "reviewSaving": [
      "Saving mark…",
      "Сохранение отметки…"
    ],
    "reviewSaved": [
      "Review mark saved locally. To hide reviewed findings, choose “Only unreviewed” and apply filters. No findings are deleted.",
      "Отметка проверки сохранена локально. Чтобы скрыть проверенные находки, выберите «Только непроверенные» и примените фильтры. Находки не удаляются."
    ],
    "reviewSavedFiltered": [
      "Review mark saved locally. Updating the filtered list automatically. No findings are deleted.",
      "Отметка проверки сохранена локально. Отфильтрованный список обновляется автоматически. Находки не удаляются."
    ],
    "any": [
      "Any",
      "Любая"
    ],
    "detectionMethod": [
      "Detection method",
      "Способ обнаружения"
    ],
    "host": [
      "Host",
      "Хост"
    ],
    "hostPlaceholder": [
      "IP or hostname",
      "IP или имя"
    ],
    "share": [
      "Share",
      "Сетевой ресурс"
    ],
    "sharePlaceholder": [
      "Share name",
      "Название ресурса"
    ],
    "pathContains": [
      "Path contains",
      "Путь содержит"
    ],
    "pathPlaceholder": [
      "Part of a path",
      "Часть пути"
    ],
    "extension": [
      "Extension",
      "Расширение"
    ],
    "category": [
      "Category",
      "Категория"
    ],
    "categoryPlaceholder": [
      "Rule category",
      "Категория правила"
    ],
    "analysisStatus": [
      "Content analysis",
      "Анализ содержимого"
    ],
    "analysis.analyzed": [
      "Analyzed",
      "Проанализировано"
    ],
    "analysis.partial": [
      "Partial",
      "Частично"
    ],
    "analysis.not_analyzed": [
      "Not analyzed",
      "Не анализировалось"
    ],
    "analysis.unknown": [
      "Unknown",
      "Неизвестно"
    ],
    "analysisReason.metadata_only": [
      "Only metadata was checked",
      "Проверялись только метаданные"
    ],
    "analysisReason.no_active_rules": [
      "No active content rules",
      "Нет активных правил содержимого"
    ],
    "analysisReason.size_policy": [
      "Excluded by size policy",
      "Исключено по ограничению размера"
    ],
    "analysisReason.format_policy": [
      "Excluded by format policy",
      "Исключено по формату"
    ],
    "analysisReason.metadata_unavailable": [
      "File metadata unavailable",
      "Метаданные файла недоступны"
    ],
    "analysisReason.scope_policy": [
      "External DFS blocked by scope policy",
      "Внешний DFS запрещён ограничениями скоупа"
    ],
    "analysisReason.read_failed": [
      "Content could not be read completely",
      "Не удалось прочитать содержимое полностью"
    ],
    "analysisReason.analysis_failed": [
      "Content analysis did not complete",
      "Анализ содержимого не завершён"
    ],
    "analysisReason.partial_analysis": [
      "Only part of the requested analysis completed",
      "Выполнена только часть запрошенного анализа"
    ],
    "analysisReason.not_started": [
      "Content analysis has not started",
      "Анализ содержимого ещё не начат"
    ],
    "analysisReason.unobserved": [
      "No recorded proof of content analysis",
      "Подтверждение анализа содержимого не сохранено"
    ],
    "sizeFrom": [
      "Minimum size, bytes",
      "Размер от, байт"
    ],
    "sizeTo": [
      "Maximum size, bytes",
      "Размер до, байт"
    ],
    "noLimit": [
      "No limit",
      "Без ограничения"
    ],
    "valueContains": [
      "Value or context contains",
      "Значение или контекст содержит"
    ],
    "searchPlaceholder": [
      "Text search, not a regular expression",
      "Текстовый поиск, не регулярное выражение"
    ],
    "applyFilters": [
      "Apply filters",
      "Применить фильтры"
    ],
    "showAll": [
      "Show all",
      "Показать всё"
    ],
    "reset": [
      "Reset",
      "Сбросить"
    ],
    "filterCaveat": [
      "Filters select files; the manual-review filter also selects matches within each file. By default all findings are shown. Review marks are local, do not delete findings and never change scanned files or scanner rules. Newly discovered objects come first. Searching values or context can take longer in large sessions.",
      "Фильтры выбирают файлы; фильтр ручной проверки также отбирает срабатывания внутри файла. По умолчанию видны все находки. Локальные отметки не удаляют находки, не изменяют сканируемые файлы или правила сканера. Сначала показаны недавно обнаруженные объекты. Поиск по значению и контексту может занимать больше времени на крупных сессиях."
    ],
    "savedView": [
      "Saved view",
      "Сохранённый набор"
    ],
    "chooseView": [
      "Choose a view",
      "Выберите набор"
    ],
    "apply": [
      "Apply",
      "Применить"
    ],
    "viewName": [
      "View name",
      "Имя набора"
    ],
    "viewPlaceholder": [
      "e.g. High-confidence keys",
      "Например, ключи высокой уверенности"
    ],
    "save": [
      "Save",
      "Сохранить"
    ],
    "deleteView": [
      "Delete view",
      "Удалить набор"
    ],
    "savedNotice": [
      "Only filter settings are saved in this browser, including entered search text. Findings themselves are not saved.",
      "Сохраняются только параметры фильтра в этом браузере, включая введённый поисковый текст. Сами находки не сохраняются."
    ],
    "objectType": [
      "Object type",
      "Тип объекта"
    ],
    "files": [
      "Files",
      "Файлы"
    ],
    "directories": [
      "Directories",
      "Каталоги"
    ],
    "shares": [
      "Shares",
      "Сетевые ресурсы"
    ],
    "hosts": [
      "Hosts",
      "Хосты"
    ],
    "allTypes": [
      "All types",
      "Все типы"
    ],
    "status": [
      "Status",
      "Состояние"
    ],
    "reasonsTitle": [
      "Skip reasons, errors and exclusions",
      "Причины пропусков и ошибок, исключения"
    ],
    "newResults": [
      "New changes — refresh results",
      "Появились изменения — обновить результаты"
    ],
    "refreshResults": [
      "Refresh results",
      "Обновить результаты"
    ],
    "previous": [
      "← Previous",
      "← Назад"
    ],
    "next": [
      "Next →",
      "Далее →"
    ],
    "firstPage": [
      "Page 1",
      "Страница 1"
    ],
    "page": [
      "Page {page}",
      "Страница {page}"
    ],
    "footer": [
      "Values are shown without masking. Do not publish screenshots containing confidential data. Live updates pause while this tab is hidden.",
      "Значения показаны без маскирования. Не публикуйте снимки экрана с конфиденциальными данными. При скрытой вкладке автообновление приостанавливается."
    ],
    "status.running": [
      "Running",
      "Выполняется"
    ],
    "status.interrupted": [
      "Interrupted",
      "Прервано"
    ],
    "status.complete": [
      "Complete",
      "Завершено"
    ],
    "status.completed": [
      "Complete",
      "Завершено"
    ],
    "status.complete_with_errors": [
      "Complete with errors",
      "Завершено с ошибками"
    ],
    "status.preflight_failed": [
      "Preflight failed",
      "Предварительная проверка не пройдена"
    ],
    "status.failed": [
      "Failed",
      "Ошибка"
    ],
    "status.pending": [
      "Pending",
      "Ожидает"
    ],
    "status.in_progress": [
      "In progress",
      "Обрабатывается"
    ],
    "status.processed": [
      "Processed",
      "Обработано"
    ],
    "status.skipped": [
      "Skipped",
      "Пропущено"
    ],
    "status.error": [
      "Error",
      "Ошибка"
    ],
    "kind.file": [
      "File",
      "Файл"
    ],
    "kind.directory": [
      "Directory",
      "Каталог"
    ],
    "kind.share": [
      "Share",
      "Сетевой ресурс"
    ],
    "kind.target": [
      "Host",
      "Хост"
    ],
    "kind.share_enumeration": [
      "Share enumeration",
      "Перечисление ресурсов"
    ],
    "severity.critical": [
      "Critical",
      "Критическая"
    ],
    "severity.high": [
      "High",
      "Высокая"
    ],
    "severity.medium": [
      "Medium",
      "Средняя"
    ],
    "severity.low": [
      "Low",
      "Низкая"
    ],
    "severity.info": [
      "Informational",
      "Информационная"
    ],
    "confidence.high": [
      "High",
      "Высокая"
    ],
    "confidence.medium": [
      "Medium",
      "Средняя"
    ],
    "confidence.low": [
      "Low",
      "Низкая"
    ],
    "representation.metadata": [
      "Metadata",
      "Метаданные"
    ],
    "representation.text": [
      "Text",
      "Текст"
    ],
    "representation.strings": [
      "Extracted strings",
      "Извлечённые строки"
    ],
    "representation.raw": [
      "Raw bytes",
      "Исходные байты"
    ],
    "representation.ocr": [
      "Recognized text",
      "Распознанный текст"
    ],
    "representation.structured": [
      "Structured data",
      "Структурированные данные"
    ],
    "representation.inspect:private-key-material": [
      "Private-key material",
      "Проверка материала закрытого ключа"
    ],
    "representation.inspect:kubernetes-secret-json": [
      "Kubernetes secrets in JSON",
      "Секреты Kubernetes в JSON"
    ],
    "representation.inspect:group-policy-preference-password": [
      "Group Policy preference passwords",
      "Пароли предпочтений групповой политики"
    ],
    "representation.inspect:active-directory-ldif-secrets": [
      "Active Directory secrets in LDIF",
      "Секреты Active Directory в LDIF"
    ],
    "representation.inspect:active-directory-json-secrets": [
      "Active Directory secrets in JSON",
      "Секреты Active Directory в JSON"
    ],
    "representation.inspect:russian-json-credential-value": [
      "Credentials under Russian JSON keys",
      "Реквизиты с русскими ключами в JSON"
    ],
    "representation.inspect:russian-legacy-credential-value": [
      "Credentials in legacy Russian encodings",
      "Реквизиты в старых русских кодировках"
    ],
    "representation.unknown": [
      "Not recorded in session",
      "Способ не указан в сессии"
    ],
    "errorNetwork": [
      "Cannot reach the local viewer. Check that it is running. Results already displayed remain on this page.",
      "Не удалось связаться с локальным просмотрщиком. Проверьте, что он запущен. Уже показанные результаты сохранены на странице."
    ],
    "errorAccess": [
      "Access to the local viewer was blocked. Open its local address directly and try again.",
      "Доступ к локальному просмотрщику заблокирован. Откройте его локальный адрес напрямую и повторите попытку."
    ],
    "error400": [
      "Check the filter settings: values and size ranges must be valid.",
      "Проверьте параметры фильтра: значения и диапазон размеров должны быть допустимыми."
    ],
    "error404": [
      "Scan unavailable. Refresh the scan list.",
      "Сканирование недоступно. Обновите список сканирований."
    ],
    "error409": [
      "Cannot open this session: unsupported schema or inaccessible local file.",
      "Не удалось открыть сессию: неподдерживаемая схема или недоступный локальный файл."
    ],
    "error422": [
      "Check the filter settings.",
      "Проверьте параметры фильтра."
    ],
    "error429": [
      "Too many requests. Try again shortly.",
      "Слишком много запросов. Повторите чуть позже."
    ],
    "error503": [
      "Results temporarily unavailable: the session is busy or the query is too expensive. Narrow the filters or try again shortly.",
      "Результаты временно недоступны: сессия занята или запрос слишком тяжёлый. Сузьте фильтры либо повторите чуть позже."
    ],
    "errorHTTP": [
      "Cannot read results (HTTP {status}). The current results are unchanged.",
      "Не удалось прочитать результаты (HTTP {status}). Текущая выдача не изменена."
    ],
    "errorJSON": [
      "The viewer returned an unexpected response format. Reload the page.",
      "Просмотрщик вернул ответ в неожиданном формате. Обновите страницу."
    ],
    "unknownSize": [
      "size unknown",
      "размер неизвестен"
    ],
    "bytes": [
      "B",
      "Б"
    ],
    "kib": [
      "KiB",
      "КиБ"
    ],
    "mib": [
      "MiB",
      "МиБ"
    ],
    "gib": [
      "GiB",
      "ГиБ"
    ],
    "tib": [
      "TiB",
      "ТиБ"
    ],
    "noScans": [
      "No saved scans found",
      "Сохранённые сканирования не найдены"
    ],
    "loadingResults": [
      "Loading results…",
      "Загрузка результатов…"
    ],
    "scanTitle": [
      "Scan {id}",
      "Сканирование {id}"
    ],
    "started": [
      "Started",
      "Начало"
    ],
    "updated": [
      "Last updated",
      "Последнее изменение"
    ],
    "finished": [
      "Finished",
      "Завершение"
    ],
    "scope": [
      "Scope",
      "Скоуп"
    ],
    "sessionFile": [
      "Session file",
      "Файл сессии"
    ],
    "filesDiscovered": [
      "Files discovered",
      "Обнаружено файлов"
    ],
    "filesProcessed": [
      "Files processed",
      "Обработано файлов"
    ],
    "filesSkipped": [
      "Files skipped",
      "Пропущено файлов"
    ],
    "filesError": [
      "Files with errors",
      "Файлов с ошибками"
    ],
    "filesPending": [
      "Pending / in progress",
      "Ожидают / в работе"
    ],
    "ruleMatches": [
      "Rule matches",
      "Срабатываний правил"
    ],
    "summaryTime": [
      "Summary: {time}",
      "Сводка: {time}"
    ],
    "scanTiming": [
      "Scan timing",
      "Время сканирования"
    ],
    "currentRunElapsed": [
      "Current run elapsed",
      "Длительность текущего запуска"
    ],
    "approximateRemaining": [
      "Approximate time remaining",
      "Примерно осталось"
    ],
    "timingCaveat": [
      "Main scan since its latest start or resume; preparation, approvals and downtime excluded. Snapshot values; estimates may change as files are discovered.",
      "Основное сканирование с последнего запуска или возобновления: без подготовки, согласований и простоя. Данные последнего обновления; оценка может меняться при обнаружении файлов."
    ],
    "timingUnavailable": [
      "Not available",
      "Нет данных"
    ],
    "timingCalculating": [
      "Calculating…",
      "Вычисляется…"
    ],
    "timingComplete": [
      "Complete",
      "Завершено"
    ],
    "timingDisabled": [
      "Estimation disabled",
      "Оценка отключена"
    ],
    "timingStale": [
      "Estimate out of date",
      "Оценка устарела"
    ],
    "timingNotStarted": [
      "Main scan not started",
      "Основное сканирование не запущено"
    ],
    "timingEstimated": [
      "≈ {duration}",
      "≈ {duration}"
    ],
    "timingRange": [
      "Estimated range: {lower}–{upper}",
      "Ориентировочный диапазон: {lower}–{upper}"
    ],
    "timingConfidence": [
      "Estimate confidence: {confidence}",
      "Уверенность в оценке: {confidence}"
    ],
    "timingUpdated": [
      "Last scan update: {time}",
      "Последнее обновление сканера: {time}"
    ],
    "durationHours": [
      "{hours} h {minutes} min {seconds} s",
      "{hours} ч {minutes} мин {seconds} с"
    ],
    "durationMinutes": [
      "{minutes} min {seconds} s",
      "{minutes} мин {seconds} с"
    ],
    "durationSeconds": [
      "{seconds} s",
      "{seconds} с"
    ],
    "type": [
      "Type",
      "Тип"
    ],
    "reason": [
      "Reason",
      "Причина"
    ],
    "count": [
      "Count",
      "Количество"
    ],
    "reasonMissing": [
      "No reason recorded",
      "Причина не указана"
    ],
    "noReasons": [
      "No skip or error reasons recorded yet.",
      "Зафиксированных причин пропусков и ошибок пока нет."
    ],
    "exclusions": [
      "Excluded before processing: {items}",
      "Исключено до постановки в обработку: {items}"
    ],
    "exclusionCaveat": [
      "Objects excluded before processing may be counted separately from the list below. The number of files inside inaccessible directories is unknown.",
      "Объекты, исключённые до постановки в обработку, могут учитываться отдельно от списка ниже. В недоступных каталогах число вложенных файлов неизвестно."
    ],
    "summaryFailed": [
      "Could not update summary",
      "Не удалось обновить сводку"
    ],
    "loadingPage": [
      "Loading page…",
      "Загрузка страницы…"
    ],
    "resultCount": [
      "On this page: {count} objects.{total}{filtered}",
      "На странице: {count} объектов.{total}{filtered}"
    ],
    "resultTotal": [
      " Total objects with findings, unfiltered: {objects}; files: {files}.",
      " Всего объектов с находками без фильтров: {objects}; из них файлов: {files}."
    ],
    "filtersActive": [
      " Filters applied.",
      " Применены фильтры."
    ],
    "pageFailed": [
      "Page not updated; previous results retained.",
      "Страница не обновлена; предыдущая выдача сохранена."
    ],
    "matchedValue": [
      "Matched value: ",
      "Совпавшее значение: "
    ],
    "value": [
      "value",
      "значение"
    ],
    "context": [
      "context",
      "контекст"
    ],
    "evidenceOpen": [
      "Full {field} — read in chunks",
      "Полное {field} — читать по частям"
    ],
    "evidenceClose": [
      "Collapse full {field}",
      "Свернуть полное {field}"
    ],
    "evidencePrevious": [
      "← Previous chunk",
      "← Предыдущий фрагмент"
    ],
    "evidenceNext": [
      "Next chunk →",
      "Следующий фрагмент →"
    ],
    "evidenceNote": [
      "The {field} preview is incomplete. The full data is preserved without masking.",
      "В предварительном просмотре {field} показано не целиком. Данные сохранены полностью, без маскирования."
    ],
    "evidencePosition": [
      "{field}: characters {start}–{end} of {total}",
      "{field}: символы {start}–{end} из {total}"
    ],
    "confidenceBadge": [
      "Confidence: {value}",
      "Уверенность: {value}"
    ],
    "categoryMeta": [
      "Category: {value}",
      "Категория: {value}"
    ],
    "tagsMeta": [
      "Tags: {value}",
      "Метки: {value}"
    ],
    "allMatches": [
      "All file matches — 50 per page",
      "Все срабатывания файла — по 50 на странице"
    ],
    "allMatchesNote": [
      "Only some matches are shown in the card. The full set is available below, without reading the network file again.",
      "В карточке показана только часть срабатываний. Полный набор доступен ниже без повторного чтения сетевого файла."
    ],
    "matchPage": [
      "Page {page}: {count} matches",
      "Страница {page}: {count} срабатываний"
    ],
    "collapseMatches": [
      "Collapse full set",
      "Свернуть полный набор"
    ],
    "filePagesChanged": [
      "This file's findings or review selection changed. The displayed evidence is retained. Restart this file's pages to continue with the current results.",
      "Находки этого файла или выборка по отметкам изменились. Показанные данные сохранены. Начните страницы этого файла заново, чтобы продолжить с актуальными результатами."
    ],
    "restartFilePages": [
      "Restart this file's pages",
      "Начать страницы этого файла заново"
    ],
    "noFindings": [
      "No findings on this page with the selected filters. Try “Show all” or wait for scan results.",
      "Нет находок на этой странице с выбранными фильтрами. Попробуйте «Показать всё» или дождитесь результатов сканирования."
    ],
    "findingsOf": [
      "{count} of {total}",
      "{count} из {total}"
    ],
    "fileDetails": [
      " · {kind} · {size}{status} · matches shown: {count}",
      " · {kind} · {size}{status} · показано срабатываний: {count}"
    ],
    "processingReason": [
      "Processing status: {reason}",
      "Состояние обработки: {reason}"
    ],
    "analysisBadge": [
      "Content: {status}",
      "Содержимое: {status}"
    ],
    "analysisReason": [
      "Content analysis: {reason}",
      "Анализ содержимого: {reason}"
    ],
    "noObjects": [
      "No objects found with the selected settings.",
      "Объекты с выбранными параметрами не найдены."
    ],
    "fullPath": [
      "Full path",
      "Полный путь"
    ],
    "size": [
      "Size",
      "Размер"
    ],
    "saveFailed": [
      "The browser could not save this view. Filters still work without saving.",
      "Браузер не разрешил сохранить набор. Фильтры продолжают работать без сохранения."
    ],
    "viewNameRequired": [
      "Enter a name for the filter view.",
      "Укажите имя набора фильтров."
    ],
    "viewLimit": [
      "The 50-view limit has been reached. Delete an unused view.",
      "Достигнут предел 50 наборов. Удалите ненужный набор."
    ],
    "viewSaved": [
      "View “{name}” saved in this browser. Included search text is saved too; findings are not.",
      "Набор «{name}» сохранён в этом браузере. Включённый поисковый текст также сохранён; сами находки — нет."
    ],
    "viewDeleted": [
      "Filter view deleted from this browser. Findings are unchanged.",
      "Набор фильтров удалён из браузера. Находки не затронуты."
    ]
  };

  const preferenceKey = "manspider.viewer.preferences.v1";
  const preferences = { language: (navigator.language || "").toLowerCase().startsWith("ru") ? "ru" : "en", theme: "system" };
  try {
    const saved = JSON.parse(localStorage.getItem(preferenceKey) || "null");
    if (saved && typeof saved === "object") {
      if (saved.language === "ru" || saved.language === "en") preferences.language = saved.language;
      if (["system", "light", "dark"].includes(saved.theme)) preferences.theme = saved.theme;
    }
  } catch (_) { /* Storage may be disabled; display preferences remain usable. */ }
  const bindings = new WeakMap();
  const locale = () => preferences.language === "ru" ? "ru-RU" : "en-US";
  const text = (value) => typeof value === "function" ? text(value()) : value == null ? "" : String(value);
  function t(key, values = {}) {
    const entry = Object.hasOwn(messages, key) ? messages[key] : null;
    const template = entry ? entry[preferences.language === "ru" ? 1 : 0] : key;
    return template.replace(/\{([a-z]+)\}/gi, (_, name) => text(values[name]));
  }
  const msg = (key, values = {}) => () => t(key, values);
  const label = (group, value) => Object.hasOwn(messages, group + "." + value) ? t(group + "." + value) : text(value);
  const named = (group, value) => () => label(group, value);
  function bindText(element, value) {
    if (typeof value === "function") bindings.set(element, value);
    else bindings.delete(element);
    if (element.nodeType === Node.ELEMENT_NODE) element.removeAttribute("data-i18n");
    element.textContent = text(value);
    return element;
  }
  function textNode(value) {
    return bindText(document.createTextNode(""), value);
  }
  function applyLanguage() {
    document.documentElement.lang = preferences.language;
    document.title = t("title");
    // Update labels in place: keep open evidence, its cursor and loaded text.
    // Weak bindings cannot retain removed pages or evidence in memory.
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    for (let element = walker.nextNode(); element; element = walker.nextNode()) {
      const binding = bindings.get(element);
      if (binding) element.textContent = text(binding);
      else if (element.nodeType === Node.ELEMENT_NODE && element.hasAttribute("data-i18n")) element.textContent = t(element.getAttribute("data-i18n"));
      if (element.nodeType === Node.ELEMENT_NODE) {
        for (const attr of ["placeholder", "aria-label"]) {
          const key = element.getAttribute("data-i18n-" + attr);
          if (key) element.setAttribute(attr, t(key));
        }
      }
    }
    byId("language-select").value = preferences.language;
  }
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  function applyTheme() {
    document.documentElement.dataset.theme = preferences.theme === "system" ? (systemTheme.matches ? "dark" : "light") : preferences.theme;
    byId("theme-select").value = preferences.theme;
  }
  function storePreferences() {
    try { localStorage.setItem(preferenceKey, JSON.stringify({ language: preferences.language, theme: preferences.theme })); }
    catch (_) { /* Never block access when preference storage is unavailable. */ }
  }

  const node = (tag, value, className) => {
    const element = document.createElement(tag);
    if (value != null) bindText(element, value);
    if (className) element.className = className;
    return element;
  };
  const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const filterNames = ["rule", "severity", "confidence", "representation", "target", "share", "path", "extension", "q", "category", "min_size", "max_size", "analysis_status", "review_status"];
  const storageKey = "manspider.viewer.filters.v1";
  const state = { scanId: "", generation: 0, view: "findings", scans: [], cursors: [0], nextAfter: null, summary: null, renderedRevision: null, latestRevision: null, resultsLoaded: false, reviewRevision: 0, listRequest: 0, summaryBusy: false, listBusy: false, filters: {}, coverageFilters: { kind: "file" } };
  let pollTimer = null;
  let pollBusy = false;
  let pageActive = true;
  let listController = null;
  let summaryController = null;
  let catalogController = null;
  let nextCatalogAt = 0;
  const errors = new Map();
  const pendingReviews = new Set();

  class ViewerError extends Error {
    constructor(value, code = "") { super(text(value)); this.localized = value; this.code = code; }
  }

  function renderErrors() {
    // Evidence errors belong to individual panels, not the entire page. Drop
    // detached panels so old pages cannot retain errors or DOM in memory.
    for (const source of errors.keys()) {
      if (source instanceof Element && !source.isConnected) errors.delete(source);
    }
    const messages = Array.from(errors.values());
    bindText(byId("error"), () => messages.map((message) => text(message instanceof Error ? (message.localized || message.message) : message)).join("\n"));
    byId("error").hidden = messages.length === 0;
  }

  function showError(message, source) {
    if (message) errors.set(source, message);
    else errors.delete(source);
    renderErrors();
  }

  function clearScanErrors() {
    for (const source of errors.keys()) if (source !== "catalog") errors.delete(source);
    renderErrors();
  }

  async function api(path, options = {}) {
    let response;
    try {
      response = await fetch(path, { method: "GET", ...options, credentials: "omit", cache: "no-store" });
    } catch (error) {
      if (error.name === "AbortError") throw error;
      throw new ViewerError(msg("errorNetwork"));
    }
    if (response.status === 401 || response.status === 403) {
      throw new ViewerError(msg("errorAccess"));
    }
    if (response.status === 409) {
      let detail;
      try { detail = await response.json(); }
      catch (error) { if (error.name === "AbortError") throw error; }
      // Only the machine-readable stale-page code permits a local restart;
      // unrelated database/schema conflicts keep their ordinary error UI.
      if (detail && detail.code === "stale_page") throw new ViewerError(msg("filePagesChanged"), "stale_page");
    }
    if (!response.ok) {
      const friendly = { 400: "error400", 404: "error404", 409: "error409", 422: "error422", 429: "error429", 503: "error503" };
      throw new ViewerError(friendly[response.status] ? msg(friendly[response.status]) : msg("errorHTTP", { status: response.status }));
    }
    try {
      return await response.json();
    } catch (error) {
      if (error.name === "AbortError") throw error;
      throw new ViewerError(msg("errorJSON"));
    }
  }

  function date(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? text(value) : parsed.toLocaleString(locale());
  }

  function number(value) {
    return Number(value || 0).toLocaleString(locale());
  }

  function size(value) {
    if (value == null) return t("unknownSize");
    const bytes = Number(value);
    if (bytes < 1024) return `${number(bytes)} ${t("bytes")}`;
    const units = ["kib", "mib", "gib", "tib"];
    let remaining = bytes / 1024;
    let index = 0;
    while (remaining >= 1024 && index < units.length - 1) { remaining /= 1024; index += 1; }
    return `${remaining.toLocaleString(locale(), { maximumFractionDigits: 1 })} ${t(units[index])}`;
  }

  function fullPath(item) {
    const path = text(item.path);
    if (path.startsWith("\\\\")) return path;
    if (!item.share) return path || text(item.target);
    if (item.kind === "share") return "\\\\" + text(item.target) + "\\" + text(item.share);
    const parts = [text(item.target), text(item.share), path.replace(/^[\\/]+/, "")].filter(Boolean);
    return "\\\\" + parts.join("\\");
  }

  function newerScan(previous, incoming) {
    // Scanner timestamps are UTC ISO strings. Compare without rounding their
    // microseconds to JS milliseconds; catalog and summary have separate caches.
    return previous && text(previous.updated_at) > text(incoming.updated_at) ? previous : incoming;
  }

  function bindScanOption(option, scan) {
    const targets = Array.isArray(scan.targets) ? scan.targets.join(", ") : "";
    bindText(option, () => `${date(scan.created_at)} · ${label("status", scan.status)} · ${targets || scan.run_id || scan.filename}`);
    option.value = text(scan.id);
  }

  function updateSelectedScan(scan) {
    const index = state.scans.findIndex((item) => text(item.id) === state.scanId);
    if (index < 0) return scan;
    const current = newerScan(state.scans[index], scan);
    state.scans[index] = current;
    const option = Array.from(byId("scan-select").options).find((item) => item.value === state.scanId);
    if (option) bindScanOption(option, current);
    return current;
  }

  async function loadScans({ refreshSummary = true } = {}) {
    if (catalogController) return;
    const controller = new AbortController();
    catalogController = controller;
    byId("reload-scans").disabled = true;
    try {
      const data = await api("/api/scans", { signal: controller.signal });
      if (controller.signal.aborted || catalogController !== controller) return;
      showError("", "catalog");
      const previous = new Map(state.scans.map((scan) => [text(scan.id), scan]));
      // Read the selection after the request: the specialist may have changed
      // it in flight. Preserve fresher summary descriptions over a cached list.
      const selected = state.scanId;
      state.scans = (Array.isArray(data.scans) ? data.scans : []).map((scan) => newerScan(scan, previous.get(text(scan.id)) || scan));
      // Discovery is bounded and can temporarily omit a busy database. Never
      // switch away from an open scan on that basis, even for an empty catalog.
      if (selected && !state.scans.some((scan) => text(scan.id) === selected) && previous.has(selected)) state.scans.push(previous.get(selected));
      const fragment = document.createDocumentFragment();
      for (const scan of state.scans) {
        const option = node("option");
        bindScanOption(option, scan);
        fragment.append(option);
      }
      byId("scan-select").replaceChildren(fragment);
      const warnings = Array.isArray(data.warnings) ? data.warnings : [];
      byId("scan-warnings").textContent = warnings.map((warning) => typeof warning === "string" ? warning : text(warning.message || warning.reason || JSON.stringify(warning))).join("\n");
      byId("scan-warnings").hidden = warnings.length === 0;
      if (state.scans.length === 0) {
        invalidateSelection();
        state.scanId = "";
        byId("scan-overview").hidden = true;
        byId("results-panel").hidden = true;
        bindText(byId("connection-state"), msg("noScans"));
        return;
      }
      const retained = state.scans.some((scan) => text(scan.id) === selected);
      byId("scan-select").value = retained ? selected : text(state.scans[0].id);
      if (!retained) await selectScan(byId("scan-select").value);
      else if (refreshSummary) await loadSummary(state.generation);
    } catch (error) {
      if (catalogController === controller && !controller.signal.aborted && error.name !== "AbortError") showError(error, "catalog");
    } finally {
      if (catalogController === controller) {
        catalogController = null;
        // Errors must not turn the catalog into a three-second retry loop.
        nextCatalogAt = controller.signal.aborted ? 0 : performance.now() + 15000;
        byId("reload-scans").disabled = false;
      }
      startPolling();
    }
  }

  function invalidateSelection() {
    state.generation += 1;
    state.listRequest += 1;
    if (listController) listController.abort();
    if (summaryController) summaryController.abort();
    state.summaryBusy = false;
    state.listBusy = false;
  }

  async function selectScan(scanId) {
    invalidateSelection();
    state.scanId = scanId;
    state.summary = null;
    state.renderedRevision = null;
    state.latestRevision = null;
    state.resultsLoaded = false;
    state.reviewRevision = 0;
    state.cursors = [0];
    state.nextAfter = null;
    byId("new-results").hidden = true;
    byId("review-notice").hidden = true;
    byId("scan-overview").hidden = true;
    byId("results-panel").hidden = false;
    byId("results").replaceChildren(node("p", msg("loadingResults"), "empty"));
    clearScanErrors();
    updatePagination();
    const generation = state.generation;
    await loadSummary(generation);
    if (generation === state.generation && pageActive && !document.hidden) await loadResults();
  }

  function detail(list, label, value) {
    list.append(node("dt", label), node("dd", value || "—"));
  }

  const validSeconds = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;
  function duration(seconds, estimated = false) {
    if (!validSeconds(seconds)) return t("timingUnavailable");
    // Estimates never imply exact completion; sub-second estimates display as
    // approximately one second. Elapsed values are the scanner's snapshot,
    // not wall time since session creation or a browser-side ticking clock.
    const whole = Math.max(estimated ? 1 : 0, Math.floor(seconds));
    const values = { hours: number(Math.floor(whole / 3600)), minutes: Math.floor(whole / 60) % 60, seconds: whole % 60 };
    return t(whole >= 3600 ? "durationHours" : whole >= 60 ? "durationMinutes" : "durationSeconds", values);
  }

  function renderTiming(timing, summaryUnavailable = false) {
    const snapshot = timing && typeof timing === "object" ? timing : {};
    let status = snapshot.eta_status;
    if (summaryUnavailable && ["estimated", "calculating"].includes(status)) status = "stale";
    const placeholders = { calculating: "timingCalculating", complete: "timingComplete", unavailable: "timingUnavailable", disabled: "timingDisabled", stale: "timingStale", not_started: "timingNotStarted" };
    bindText(byId("scan-elapsed"), validSeconds(snapshot.elapsed_seconds)
      ? () => duration(snapshot.elapsed_seconds)
      : msg(status === "not_started" ? "timingNotStarted" : "timingUnavailable"));
    const estimated = status === "estimated" && validSeconds(snapshot.remaining_seconds);
    bindText(byId("scan-remaining"), estimated
      ? msg("timingEstimated", { duration: () => duration(snapshot.remaining_seconds, true) })
      : msg(Object.hasOwn(placeholders, status) ? placeholders[status] : "timingUnavailable"));
    const rangeAvailable = estimated && validSeconds(snapshot.lower_seconds) && validSeconds(snapshot.upper_seconds) && snapshot.lower_seconds <= snapshot.upper_seconds;
    const confidenceAvailable = estimated && ["low", "medium", "high"].includes(snapshot.confidence);
    bindText(byId("scan-timing-estimate"), () => {
      const details = [];
      if (rangeAvailable) details.push(t("timingRange", { lower: duration(snapshot.lower_seconds, true), upper: duration(snapshot.upper_seconds, true) }));
      if (confidenceAvailable) details.push(t("timingConfidence", { confidence: label("confidence", snapshot.confidence) }));
      return details.join(" · ");
    });
    byId("scan-timing-estimate").hidden = !rangeAvailable && !confidenceAvailable;
    const updated = typeof snapshot.updated_at === "string" && Number.isFinite(Date.parse(snapshot.updated_at));
    bindText(byId("scan-timing-updated"), updated ? msg("timingUpdated", { time: () => date(snapshot.updated_at) }) : "");
    byId("scan-timing-updated").hidden = !updated;
  }

  function renderSummary(data) {
    const scan = data.scan || {};
    byId("scan-overview").hidden = false;
    bindText(byId("scan-status"), named("status", scan.status));
    bindText(byId("scan-title"), msg("scanTitle", { id: scan.run_id || "" }));
    const details = document.createDocumentFragment();
    detail(details, msg("started"), () => date(scan.created_at));
    detail(details, msg("updated"), () => date(scan.updated_at));
    if (scan.completed_at) detail(details, msg("finished"), () => date(scan.completed_at));
    detail(details, msg("scope"), Array.isArray(scan.targets) ? scan.targets.join(", ") : "—");
    if (scan.filename) detail(details, msg("sessionFile"), scan.filename);
    byId("scan-details").replaceChildren(details);
    const files = (data.objects || {}).file || {};
    const discovered = Object.values(files).reduce((sum, count) => sum + Number(count || 0), 0);
    const cards = [[msg("filesDiscovered"), discovered], [msg("filesProcessed"), files.processed], [msg("filesSkipped"), files.skipped], [msg("filesError"), files.error], [msg("filesPending"), Number(files.pending || 0) + Number(files.in_progress || 0)], [msg("ruleMatches"), data.findings]];
    const metrics = document.createDocumentFragment();
    for (const [label, value] of cards) {
      const card = node("div", null, "metric");
      card.append(node("strong", () => number(value)), node("span", label));
      metrics.append(card);
    }
    byId("metrics").replaceChildren(metrics);
    renderTiming(data.timing);
    const analysis = data.analysis_counts || {};
    const analysisMetrics = document.createDocumentFragment();
    for (const status of ["analyzed", "partial", "not_analyzed", "unknown"]) {
      const value = analysis[status] == null ? (status === "unknown" ? discovered : 0) : analysis[status];
      const card = node("div", null, "metric analysis-metric");
      card.dataset.analysis = status;
      card.append(node("strong", () => number(value)), node("span", named("analysis", status)));
      analysisMetrics.append(card);
    }
    byId("analysis-metrics").replaceChildren(analysisMetrics);
    byId("analysis-legacy-note").hidden = data.analysis_counts_available === true;
    renderReasons(data);
    const summaryAt = new Date();
    bindText(byId("connection-state"), msg("summaryTime", { time: () => summaryAt.toLocaleTimeString(locale()) }));
  }

  function renderReasons(data) {
    const fragment = document.createDocumentFragment();
    const reasons = Array.isArray(data.reasons) ? data.reasons : [];
    if (reasons.length) {
      const table = node("table");
      const header = node("tr");
      for (const label of [msg("type"), msg("status"), msg("reason"), msg("count")]) header.append(node("th", label));
      const head = node("thead"); head.append(header); table.append(head);
      const body = node("tbody");
      for (const reason of reasons) {
        const row = node("tr");
        row.append(node("td", named("kind", reason.kind)), node("td", named("status", reason.status)), node("td", reason.reason || msg("reasonMissing"), "reason-cell"), node("td", () => number(reason.count)));
        body.append(row);
      }
      table.append(body);
      const wrapper = node("div", null, "table-wrap"); wrapper.append(table); fragment.append(wrapper);
    } else fragment.append(node("p", msg("noReasons"), "muted"));
    const exclusions = Object.entries(data.exclusions || {});
    if (exclusions.length) fragment.append(node("p", msg("exclusions", { items: () => exclusions.map(([kind, count]) => `${label("kind", kind)} — ${number(count)}`).join("; ") }), "compact"));
    fragment.append(node("p", msg("exclusionCaveat"), "muted compact"));
    byId("reasons").replaceChildren(fragment);
  }

  async function loadSummary(generation = state.generation) {
    if (!state.scanId || state.summaryBusy) return;
    state.summaryBusy = true;
    const controller = new AbortController();
    summaryController = controller;
    try {
      const data = await api(`/api/scans/${encodeURIComponent(state.scanId)}/summary`, { signal: controller.signal });
      if (generation !== state.generation || controller.signal.aborted) return;
      data.scan = updateSelectedScan(data.scan || {});
      state.summary = data;
      state.latestRevision = JSON.stringify(data.results_revision ?? data.revision);
      renderSummary(data);
      // A successfully loaded page can have an unknown revision when the first
      // summary failed. Ask for an explicit refresh instead of silencing updates.
      if (state.resultsLoaded && state.latestRevision !== state.renderedRevision) byId("new-results").hidden = false;
      showError("", "summary");
    } catch (error) {
      if (generation === state.generation && !controller.signal.aborted && error.name !== "AbortError") {
        bindText(byId("connection-state"), msg("summaryFailed"));
        if (state.summary) renderTiming(state.summary.timing, true);
        showError(error, "summary");
      }
    } finally {
      if (summaryController === controller) state.summaryBusy = false;
    }
  }

  function readFilters() {
    const values = {};
    for (const name of filterNames) {
      const input = byId("filters").elements.namedItem(name);
      if (input.value.trim()) values[name] = input.value.trim();
    }
    return values;
  }

  function applyFilterValues(values) {
    for (const name of filterNames) {
      const input = byId("filters").elements.namedItem(name);
      input.value = text(values[name]).slice(0, input.maxLength > 0 ? input.maxLength : 512);
    }
  }

  function updatePagination() {
    byId("previous-page").disabled = state.listBusy || state.cursors.length <= 1;
    byId("next-page").disabled = state.listBusy || state.nextAfter == null;
    bindText(byId("page-number"), msg("page", { page: () => number(state.cursors.length) }));
    byId("refresh-results").disabled = state.listBusy;
  }

  async function loadResults({ preserveOpen = false } = {}) {
    if (!state.scanId) return;
    if (listController) listController.abort();
    const controller = new AbortController(); listController = controller;
    const generation = state.generation;
    const request = ++state.listRequest;
    const revision = state.latestRevision;
    const reviewRevision = state.reviewRevision;
    const view = state.view;
    const filters = view === "findings" ? state.filters : state.coverageFilters;
    const query = new URLSearchParams({ limit: "100", after: text(state.cursors[state.cursors.length - 1]), ...filters });
    state.listBusy = true;
    updatePagination();
    const previousCount = bindings.get(byId("result-count")) || byId("result-count").textContent;
    bindText(byId("result-count"), msg("loadingPage"));
    try {
      const data = await api(`/api/scans/${encodeURIComponent(state.scanId)}/${view === "findings" ? "findings" : "objects"}?${query}`, { signal: controller.signal });
      if (generation !== state.generation || request !== state.listRequest || controller.signal.aborted) return;
      // A GET started before a successful mark must not overwrite the newer UI.
      if (reviewRevision !== state.reviewRevision) {
        bindText(byId("result-count"), previousCount);
        return false;
      }
      const items = Array.isArray(data.items) ? data.items : [];
      if (view === "findings") renderFindings(items, filters.review_status || "", preserveOpen);
      else renderObjects(items);
      state.nextAfter = data.next_after == null ? null : data.next_after;
      state.renderedRevision = revision;
      state.resultsLoaded = true;
      byId("new-results").hidden = state.latestRevision === state.renderedRevision;
      byId("review-notice").hidden = true;
      const summary = state.summary;
      const total = view === "findings" ? msg("resultTotal", { objects: () => number(summary && summary.matched_objects), files: () => number(summary && summary.matched_files) }) : "";
      const activeFilter = view === "findings" && Object.values(state.filters).some(Boolean);
      bindText(byId("result-count"), msg("resultCount", { count: () => number(items.length), total, filtered: activeFilter ? msg("filtersActive") : "" }));
      showError("", "results");
      return true;
    } catch (error) {
      if (generation === state.generation && request === state.listRequest && !controller.signal.aborted && error.name !== "AbortError") {
        bindText(byId("result-count"), msg("pageFailed"));
        showError(error, "results");
      }
      return false;
    } finally {
      if (request === state.listRequest) { state.listBusy = false; updatePagination(); }
    }
  }

  function badge(value, className = "") {
    return node("span", value, `badge ${className}`.trim());
  }

  function appendContext(container, finding, scanId) {
    const value = text(finding.value);
    const context = finding.context == null ? value : text(finding.context);
    const block = node("pre", null, "context");
    // Stored match_start/end refer to the original representation, not the
    // context substring. Highlight an exact value only; never guess offsets.
    const offset = value ? context.indexOf(value) : -1;
    if (offset >= 0) {
      block.append(document.createTextNode(context.slice(0, offset)), node("mark", value), document.createTextNode(context.slice(offset + value.length)));
    } else {
      block.textContent = context;
    }
    container.append(block);
    if (offset < 0 && value) {
      const separate = node("p", null, "context");
      separate.append(textNode(msg("matchedValue")), node("mark", value));
      container.append(separate);
    }
    for (const field of ["value", "context"]) {
      if (!finding[`${field}_truncated`] || !finding.finding_id) continue;
      const fieldName = msg(field);
      const open = node("button", msg("evidenceOpen", { field: fieldName }), "secondary");
      open.type = "button";
      const viewer = node("div", null, "evidence-viewer");
      viewer.hidden = true;
      const chunk = node("pre", null, "context");
      const toolbar = node("div", null, "evidence-toolbar");
      const previous = node("button", msg("evidencePrevious"), "secondary"); previous.type = "button";
      const next = node("button", msg("evidenceNext"), "secondary"); next.type = "button";
      const position = node("span", "", "muted compact");
      toolbar.append(previous, position, next); viewer.append(chunk, toolbar);
      container.append(node("p", msg("evidenceNote", { field: fieldName }), "muted compact"), open, viewer);
      const offsets = [0];
      let nextOffset = null;
      let busy = false;
      async function loadChunk(offset) {
        if (busy) return false;
        busy = true; open.disabled = true; previous.disabled = true; next.disabled = true;
        try {
          const query = new URLSearchParams({ field, offset: text(offset), limit: "65536" });
          const data = await api(`/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(finding.finding_id)}/evidence?${query}`);
          if (state.scanId !== scanId || !container.isConnected) return false;
          if (field === "value") chunk.replaceChildren(node("mark", data.text));
          else chunk.textContent = text(data.text);
          nextOffset = data.next_offset == null ? null : data.next_offset;
          const end = nextOffset == null ? data.total : nextOffset;
          bindText(position, msg("evidencePosition", { field: fieldName, start: () => number(Number(offset) + 1), end: () => number(end), total: () => number(data.total) }));
          viewer.hidden = false;
          bindText(open, msg("evidenceClose", { field: fieldName }));
          showError("", viewer);
          return true;
        } catch (error) {
          if (state.scanId === scanId && container.isConnected) showError(error, viewer);
          return false;
        } finally {
          busy = false; open.disabled = false;
          previous.disabled = offsets.length <= 1;
          next.disabled = nextOffset == null;
        }
      }
      open.addEventListener("click", () => {
        if (!viewer.hidden) { viewer.hidden = true; bindText(open, msg("evidenceOpen", { field: fieldName })); return; }
        loadChunk(offsets[offsets.length - 1]);
      });
      previous.addEventListener("click", async () => {
        if (busy || offsets.length <= 1) return;
        const old = offsets.pop();
        if (!await loadChunk(offsets[offsets.length - 1])) offsets.push(old);
        previous.disabled = offsets.length <= 1;
      });
      next.addEventListener("click", async () => {
        if (busy || nextOffset == null) return;
        offsets.push(nextOffset);
        if (!await loadChunk(nextOffset)) offsets.pop();
        previous.disabled = offsets.length <= 1;
      });
    }
  }

  function updateReviewCopies(findingId, reviewed, busy) {
    for (const article of byId("results").querySelectorAll("article[data-finding-id]")) {
      if (article.dataset.findingId !== findingId) continue;
      if (reviewed != null) article.dataset.reviewed = text(reviewed);
      const checked = article.dataset.reviewed === "true";
      article.classList.toggle("reviewed-finding", checked);
      bindText(article.querySelector(".review-badge"), msg(checked ? "reviewed" : "unreviewed"));
      const button = article.querySelector(".review-toggle");
      button.disabled = busy;
      button.setAttribute("aria-busy", text(busy));
      bindText(button, msg(busy ? "reviewSaving" : checked ? "markUnreviewed" : "markReviewed"));
    }
  }

  function appendReviewControls(header, article, finding, context) {
    if (finding.finding_id == null) return;
    const findingId = text(finding.finding_id);
    const key = JSON.stringify([context.generation, context.scanId, findingId]);
    article.dataset.findingId = findingId;
    article.dataset.reviewed = text(finding.reviewed === true);
    article.classList.toggle("reviewed-finding", finding.reviewed === true);
    const status = badge(msg(finding.reviewed === true ? "reviewed" : "unreviewed"), "review-badge");
    const toggle = node("button", msg(pendingReviews.has(key) ? "reviewSaving" : finding.reviewed === true ? "markUnreviewed" : "markReviewed"), "secondary review-toggle");
    toggle.type = "button";
    toggle.disabled = pendingReviews.has(key);
    toggle.setAttribute("aria-busy", text(toggle.disabled));
    header.append(status, toggle);
    toggle.addEventListener("click", async () => {
      if (pendingReviews.has(key) || !article.isConnected || context.generation !== state.generation || context.scanId !== state.scanId) return;
      const reviewed = article.dataset.reviewed !== "true";
      pendingReviews.add(key);
      updateReviewCopies(findingId, null, true);
      showError("", article);
      try {
        // Only an explicit specialist action writes a local review mark. The
        // browser supplies Origin; the custom header prevents simple CSRF.
        const data = await api(`/api/scans/${encodeURIComponent(context.scanId)}/findings/${encodeURIComponent(findingId)}/review`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json", "X-Manspider-Review": "1" },
          body: JSON.stringify({ reviewed }),
        });
        if (context.generation !== state.generation || context.scanId !== state.scanId) return;
        if (text(data.finding_id) !== findingId || data.reviewed !== reviewed) throw new ViewerError(msg("errorJSON"));
        state.reviewRevision += 1;
        updateReviewCopies(findingId, reviewed, true);
        bindText(byId("review-notice"), msg(state.filters.review_status ? "reviewSavedFiltered" : "reviewSaved"));
        byId("review-notice").hidden = false;
        byId("new-results").hidden = false;
        showError("", article);
        // Re-query the current page only after the mark is durable. The server
        // decides whether a file still matches all applied filters; a truncated
        // preview cannot answer that. Never apply unsaved form edits or reset
        // pagination. Ordinary live scan updates still require explicit refresh.
        if (state.view === "findings" && state.filters.review_status) await loadResults({ preserveOpen: true });
      } catch (error) {
        if (context.generation === state.generation && context.scanId === state.scanId && article.isConnected) showError(error, article);
      } finally {
        pendingReviews.delete(key);
        if (context.generation === state.generation && context.scanId === state.scanId) updateReviewCopies(findingId, null, false);
      }
    });
  }

  function findingArticle(finding, context) {
    const article = node("article", null, "finding");
    const header = node("div", null, "finding-header");
    const severity = Object.hasOwn(severityOrder, finding.severity) ? finding.severity : "info";
    header.append(node("span", finding.rule_id, "rule-name"), badge(named("severity", finding.severity), `severity-${severity}`), badge(msg("confidenceBadge", { value: named("confidence", finding.confidence) })), badge(named("representation", finding.representation)));
    appendReviewControls(header, article, finding, context);
    article.append(header);
    const meta = [];
    if (finding.category) meta.push(msg("categoryMeta", { value: finding.category }));
    if (Array.isArray(finding.tags) && finding.tags.length) meta.push(msg("tagsMeta", { value: finding.tags.join(", ") }));
    if (meta.length) article.append(node("p", () => meta.map(text).join(" · "), "finding-meta"));
    appendContext(article, finding, context.scanId);
    return article;
  }

  function fullFindingPages(container, item, context) {
    const { scanId, generation, reviewStatus } = context;
    const previewArticles = Array.from(container.children).filter((child) => child.classList.contains("finding"));
    const open = node("button", msg("allMatches"), "secondary"); open.type = "button";
    const content = node("div"); content.hidden = true;
    const rows = node("div");
    const toolbar = node("div", null, "evidence-toolbar");
    const previous = node("button", msg("previous"), "secondary"); previous.type = "button";
    const next = node("button", msg("next"), "secondary"); next.type = "button";
    const position = node("span", "", "muted compact");
    const notice = node("div", null, "file-page-notice"); notice.hidden = true;
    notice.setAttribute("role", "status");
    const restart = node("button", msg("restartFilePages"), "secondary restart-file-pages"); restart.type = "button";
    notice.append(node("p", msg("filePagesChanged"), "compact"), restart);
    toolbar.append(previous, position, next); content.append(rows, toolbar);
    container.append(node("p", msg("allMatchesNote"), "truncated"), open, notice, content);
    let cursors = [0]; let nextAfter = null; let busy = false; let pageToken = null; let stale = false;
    function updateControls() {
      open.disabled = busy;
      restart.disabled = busy;
      previous.disabled = busy || stale || cursors.length <= 1;
      next.disabled = busy || stale || nextAfter == null;
    }
    function revealPage() {
      content.hidden = false; bindText(open, msg("collapseMatches"));
      for (const article of previewArticles) article.hidden = true;
    }
    async function loadPage(candidateCursors, reset = false) {
      if (busy) return false;
      const cursor = candidateCursors[candidateCursors.length - 1];
      const requestToken = reset ? null : pageToken;
      busy = true; updateControls();
      const reviewRevision = state.reviewRevision;
      try {
        const query = new URLSearchParams({ limit: "50", after: text(cursor) });
        if (reviewStatus) query.set("review_status", reviewStatus);
        if (requestToken != null) query.set("page_token", requestToken);
        const data = await api(`/api/scans/${encodeURIComponent(scanId)}/objects/${encodeURIComponent(item.object_id)}/findings?${query}`);
        if (state.scanId !== scanId || generation !== state.generation || !container.isConnected || reviewRevision !== state.reviewRevision) return false;
        if (typeof data.page_token !== "string" || !data.page_token) throw new ViewerError(msg("errorJSON"));
        if (requestToken != null && requestToken !== data.page_token) throw new ViewerError(msg("filePagesChanged"), "stale_page");
        const fragment = document.createDocumentFragment();
        for (const finding of data.items || []) fragment.append(findingArticle(finding, context));
        rows.replaceChildren(fragment);
        // Commit navigation only after a successful, current-generation reply.
        // A failed Next, Previous, reopen or restart retains the visible page.
        cursors = candidateCursors;
        pageToken = data.page_token;
        nextAfter = data.next_after == null ? null : data.next_after;
        const page = cursors.length;
        bindText(position, msg("matchPage", { page: () => number(page), count: () => number((data.items || []).length) }));
        stale = false; notice.hidden = true;
        revealPage();
        showError("", content);
        return true;
      } catch (error) {
        if (state.scanId === scanId && generation === state.generation && container.isConnected && reviewRevision === state.reviewRevision) {
          if (error.code === "stale_page") {
            stale = true; notice.hidden = false;
            showError("", content);
          } else showError(error, content);
        }
        return false;
      } finally {
        busy = false; updateControls();
      }
    }
    open.addEventListener("click", () => {
      if (!content.hidden) {
        content.hidden = true; bindText(open, msg("allMatches"));
        for (const article of previewArticles) article.hidden = false;
        return;
      }
      if (stale) { if (pageToken != null) revealPage(); return; }
      loadPage(cursors);
    });
    previous.addEventListener("click", () => {
      if (busy || stale || cursors.length <= 1) return;
      loadPage(cursors.slice(0, -1));
    });
    next.addEventListener("click", () => {
      if (busy || stale || nextAfter == null) return;
      loadPage([...cursors, nextAfter]);
    });
    restart.addEventListener("click", () => { if (!busy) loadPage([0], true); });
  }

  function renderFindings(items, reviewStatus = "", preserveOpen = false) {
    const context = { scanId: state.scanId, generation: state.generation, reviewStatus };
    // Read expansion state at render time, so opening/closing a card while the
    // refresh was in flight is respected. File-page cursors are not reused:
    // changing review membership invalidates their result-set version.
    const openObjects = new Set(preserveOpen ? Array.from(byId("results").querySelectorAll("details.file-result[open]"), (card) => card.dataset.objectId) : []);
    const fragment = document.createDocumentFragment();
    if (!items.length) fragment.append(node("p", msg("noFindings"), "empty"));
    for (const item of items) {
      const findings = Array.isArray(item.findings) ? item.findings : [];
      const details = node("details", null, "file-result");
      details.dataset.objectId = text(item.object_id);
      details.open = openObjects.has(details.dataset.objectId);
      const summary = node("summary");
      summary.append(node("span", fullPath(item), "file-path"));
      const strongest = item.max_severity || findings.reduce((best, finding) => (severityOrder[finding.severity] || 0) > (severityOrder[best] || 0) ? finding.severity : best, "info");
      const info = node("span", null, "file-details");
      const findingCount = item.total_findings == null ? () => number(findings.length) : msg("findingsOf", { count: () => number(findings.length), total: () => number(item.total_findings) });
      info.append(badge(named("severity", strongest), `severity-${Object.hasOwn(severityOrder, strongest) ? strongest : "info"}`), textNode(msg("fileDetails", { kind: named("kind", item.kind || "file"), size: () => item.kind && item.kind !== "file" ? "" : size(item.size) + " · ", status: named("status", item.status), count: findingCount })));
      if (!item.kind || item.kind === "file") info.append(textNode(" · "), badge(msg("analysisBadge", { status: named("analysis", item.analysis_status || "unknown") })));
      summary.append(info); details.append(summary);
      // Build context DOM lazily. A page never renders every file's complete
      // evidence until the specialist explicitly opens that file.
      let built = false;
      details.addEventListener("toggle", () => {
        if (!details.open || built) return;
        built = true;
        for (const finding of findings) {
          details.append(findingArticle(finding, context));
        }
        if (item.findings_truncated || Number(item.total_findings || 0) > findings.length) fullFindingPages(details, item, context);
        if (item.reason) details.append(node("p", msg("processingReason", { reason: item.reason }), "finding-meta finding"));
        if (item.analysis_reason && (!item.kind || item.kind === "file")) details.append(node("p", msg("analysisReason", { reason: named("analysisReason", item.analysis_reason) }), "finding-meta finding"));
      });
      fragment.append(details);
    }
    byId("results").replaceChildren(fragment);
  }

  function renderObjects(items) {
    if (!items.length) { byId("results").replaceChildren(node("p", msg("noObjects"), "empty")); return; }
    const wrapper = node("div", null, "table-wrap");
    const table = node("table");
    const head = node("thead"); const header = node("tr");
    for (const title of [msg("fullPath"), msg("type"), msg("size"), msg("status"), msg("analysisStatus"), msg("reason")]) header.append(node("th", title));
    head.append(header); table.append(head);
    const body = node("tbody");
    for (const item of items) {
      const row = node("tr");
      // Only bind leaf text: changing language must not remove the reason.
      const analysis = node("td");
      analysis.append(node("span", item.kind === "file" ? named("analysis", item.analysis_status || "unknown") : "—"));
      if (item.kind === "file" && item.analysis_reason) analysis.append(node("p", named("analysisReason", item.analysis_reason), "finding-meta"));
      row.append(node("td", fullPath(item), "path-cell"), node("td", named("kind", item.kind)), node("td", item.kind === "file" ? () => size(item.size) : "—"), node("td", named("status", item.status)), analysis, node("td", item.reason || "—", "reason-cell"));
      body.append(row);
    }
    table.append(body); wrapper.append(table); byId("results").replaceChildren(wrapper);
  }

  function restartResults() { state.cursors = [0]; state.nextAfter = null; return loadResults(); }

  function switchView(view) {
    if (state.view === view) return;
    state.view = view;
    const findings = view === "findings";
    byId("findings-controls").hidden = !findings;
    byId("coverage-controls").hidden = findings;
    for (const [id, active] of [["tab-findings", findings], ["tab-coverage", !findings]]) {
      byId(id).classList.toggle("active", active);
      byId(id).setAttribute("aria-pressed", text(active));
    }
    restartResults();
  }

  function savedFilters() {
    try {
      const value = JSON.parse(localStorage.getItem(storageKey) || "[]");
      if (!Array.isArray(value)) return [];
      // Saved views can outlive supported filters. Keep only current names
      // so retired options cannot silently change results or reach the API.
      return value.filter((entry) => entry && typeof entry.name === "string" && entry.filters && typeof entry.filters === "object").slice(0, 50).map((entry) => ({
        name: entry.name,
        filters: Object.fromEntries(Object.entries(entry.filters).filter(([name]) => filterNames.includes(name))),
      }));
    } catch (_) { return []; }
  }

  function refreshSavedFilters(selected = "") {
    const select = byId("saved-select");
    const empty = node("option", msg("chooseView")); empty.value = "";
    select.replaceChildren(empty);
    for (const [index, entry] of savedFilters().entries()) {
      const option = node("option", entry.name); option.value = text(index); select.append(option);
    }
    select.value = selected;
  }

  function storeFilters(entries) {
    try { localStorage.setItem(storageKey, JSON.stringify(entries)); return true; }
    catch (_) { bindText(byId("saved-notice"), msg("saveFailed")); return false; }
  }

  function stopPolling() { if (pollTimer !== null) window.clearTimeout(pollTimer); pollTimer = null; }
  async function pollOnce() {
    if (!pageActive || document.hidden || pollBusy) return;
    pollBusy = true;
    try {
      const generation = state.generation;
      if (performance.now() >= nextCatalogAt) await loadScans({ refreshSummary: false });
      // A newly selected scan already loads its own initial summary/page.
      if (pageActive && !document.hidden && generation === state.generation) await loadSummary();
      // Initial discovery can be interrupted by hiding the tab. Load only a
      // still-missing first page on return; never replace an existing page.
      if (pageActive && !document.hidden && !state.resultsLoaded && !state.listBusy) await loadResults();
    } finally {
      pollBusy = false;
      startPolling();
    }
  }

  function startPolling() {
    if (!pageActive || document.hidden || pollBusy || pollTimer !== null) return;
    pollTimer = window.setTimeout(async () => {
      pollTimer = null;
      await pollOnce();
    }, 3000);
  }

  byId("scan-select").addEventListener("change", (event) => selectScan(event.target.value));
  byId("reload-scans").addEventListener("click", () => loadScans());
  byId("filters").addEventListener("submit", (event) => { event.preventDefault(); state.filters = readFilters(); restartResults(); });
  byId("show-all").addEventListener("click", () => { applyFilterValues({}); state.filters = readFilters(); restartResults(); });
  byId("reset-filters").addEventListener("click", () => { byId("filters").reset(); state.filters = readFilters(); restartResults(); });
  byId("coverage-filters").addEventListener("submit", (event) => { event.preventDefault(); state.coverageFilters = Object.fromEntries(new FormData(event.currentTarget)); restartResults(); });
  byId("tab-findings").addEventListener("click", () => switchView("findings"));
  byId("tab-coverage").addEventListener("click", () => switchView("coverage"));
  async function movePage(forward) {
    if (state.listBusy || (forward ? state.nextAfter == null : state.cursors.length <= 1)) return;
    const previousCursors = [...state.cursors];
    const generation = state.generation;
    const request = state.listRequest + 1;
    if (forward) state.cursors.push(state.nextAfter);
    else state.cursors.pop();
    const success = await loadResults();
    if (generation !== state.generation || request !== state.listRequest) return;
    if (!success) { state.cursors = previousCursors; updatePagination(); }
    else byId("results").scrollIntoView({ block: "start" });
  }
  byId("previous-page").addEventListener("click", () => movePage(false));
  byId("next-page").addEventListener("click", () => movePage(true));
  byId("refresh-results").addEventListener("click", restartResults);
  byId("new-results").addEventListener("click", restartResults);
  byId("save-filter").addEventListener("click", () => {
    const name = byId("saved-name").value.trim();
    if (!name) { bindText(byId("saved-notice"), msg("viewNameRequired")); byId("saved-name").focus(); return; }
    const entries = savedFilters();
    const index = entries.findIndex((entry) => entry.name === name);
    if (index >= 0) entries[index] = { name, filters: readFilters() };
    else if (entries.length < 50) entries.push({ name, filters: readFilters() });
    else { bindText(byId("saved-notice"), msg("viewLimit")); return; }
    if (storeFilters(entries)) { refreshSavedFilters(text(index >= 0 ? index : entries.length - 1)); bindText(byId("saved-notice"), msg("viewSaved", { name })); }
  });
  byId("load-filter").addEventListener("click", () => {
    if (byId("saved-select").value === "") return;
    const entry = savedFilters()[Number(byId("saved-select").value)];
    if (!entry) return;
    applyFilterValues(entry.filters); byId("saved-name").value = entry.name; state.filters = readFilters(); restartResults();
  });
  byId("delete-filter").addEventListener("click", () => {
    if (byId("saved-select").value === "") return;
    const entries = savedFilters(); entries.splice(Number(byId("saved-select").value), 1);
    if (storeFilters(entries)) { refreshSavedFilters(); bindText(byId("saved-notice"), msg("viewDeleted")); }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      stopPolling();
      if (summaryController) summaryController.abort();
      if (catalogController) catalogController.abort();
    } else { stopPolling(); pollOnce(); }
  });
  window.addEventListener("pagehide", () => {
    pageActive = false;
    stopPolling();
    if (summaryController) summaryController.abort();
    if (catalogController) catalogController.abort();
    if (listController) listController.abort();
  });
  window.addEventListener("pageshow", (event) => { if (event.persisted) { pageActive = true; pollOnce(); } });
  window.addEventListener("hashchange", clearFragment);

  byId("language-select").addEventListener("change", (event) => {
    if (!["ru", "en"].includes(event.target.value)) return;
    preferences.language = event.target.value;
    applyLanguage();
    storePreferences();
  });
  byId("theme-select").addEventListener("change", (event) => {
    if (!["system", "light", "dark"].includes(event.target.value)) return;
    preferences.theme = event.target.value;
    applyTheme();
    storePreferences();
  });
  systemTheme.addEventListener("change", () => { if (preferences.theme === "system") applyTheme(); });

  applyTheme();
  applyLanguage();
  refreshSavedFilters();
  loadScans();
})();
