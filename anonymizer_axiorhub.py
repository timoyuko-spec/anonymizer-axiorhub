"""
title: Anonymizer-Axiorhub
author: Timo
version: 2.2.1
license: MIT
description: Outil Open WebUI pour anonymiser/désanonymiser les prompts avec mapping persistant SQLite,
             séparation nette entre détection structurée et détection des personnes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Dict, List, Optional, Tuple
import json
import sqlite3
import time
import uuid

import regex as re
from pydantic import BaseModel, Field

try:
    from presidio_analyzer import (
        AnalyzerEngine,
        Pattern,
        PatternRecognizer,
        RecognizerRegistry,
    )
except Exception:  # pragma: no cover
    AnalyzerEngine = None  # type: ignore[assignment]
    Pattern = None  # type: ignore[assignment]
    PatternRecognizer = None  # type: ignore[assignment]
    RecognizerRegistry = None  # type: ignore[assignment]


TOKEN_RE = re.compile(r"\[(?:PERSON_\d+_)?[A-Z_]+_\d+\]")

STRUCTURED_TYPES = {
    "EMAIL_CUSTOM",
    "IBAN_CUSTOM",
    "PHONE_FR",
    "PHONE_NUMBER",
    "NIR",
    "SIRET",
    "SIREN",
    "RCS",
}

PERSON_TYPES = {
    "PERSON_FR",
    "PERSON",
}

ENTITY_PRIORITY = {
    "NIR": 100,
    "IBAN_CUSTOM": 95,
    "EMAIL_CUSTOM": 95,
    "PHONE_FR": 90,
    "PHONE_NUMBER": 90,
    "SIRET": 90,
    "SIREN": 90,
    "RCS": 90,
    "PERSON_FR": 60,
    "PERSON": 50,
    "LOCATION": 40,
    "DATE_TIME": 40,
}


class Valves(BaseModel):
    sqlite_path: str = Field(default="/data/pii_map.sqlite")
    mapping_ttl_hours: int = Field(default=24, ge=1, le=720)
    score_threshold: float = Field(default=0.35, ge=0.0, le=1.0)

    enable_persistence: bool = Field(default=True)
    persist_original_text: bool = Field(
        default=False,
        description="Stocker le texte original. Désactivé par défaut pour limiter l'exposition.",
    )

    enable_person_fr: bool = True
    enable_person: bool = False

    enable_siret: bool = True
    enable_siren: bool = True
    enable_rcs: bool = True
    enable_nir: bool = True
    enable_email: bool = True
    enable_iban: bool = True
    enable_phone_fr: bool = True
    enable_phone: bool = False

    enable_location: bool = False
    enable_datetime: bool = False

    person_window_chars: int = Field(default=120, ge=20, le=1000)
    presidio_language: str = Field(default="en")


@dataclass
class SimpleResult:
    entity_type: str
    start: int
    end: int
    score: float


@dataclass
class ClusteredEntity:
    entity_type: str
    start: int
    end: int
    score: float
    text: str
    person_id: Optional[int] = None


class Tools:
    def __init__(self, valves: Optional[Valves] = None) -> None:
        self.valves = valves or Valves()
        self._db_lock = RLock()
        self._structured_regex = self._build_structured_regex_recognizers()
        self._person_regex = self._build_person_regex_recognizers()
        self.registry = None
        self.analyzer = None
        self._setup_presidio()
        self._init_db()

    # -------------------------
    # API Open WebUI
    # -------------------------

    async def anonymize_prompt(self, text: str) -> str:
        anonymized_text, mapping_id = self.anonymize_text_with_mapping(text)
        if mapping_id:
            return f"{anonymized_text}\n\n[MAPPING_ID={mapping_id}]"
        return anonymized_text

    async def deanonymize_prompt(self, text: str, mapping_id: str) -> str:
        if not text or not mapping_id:
            return text
        return self.deanonymize_text(text, mapping_id)

    # -------------------------
    # API proxy / interne
    # -------------------------

    def anonymize_text_with_mapping(self, text: str) -> Tuple[str, Optional[str]]:
        if not text:
            return text, None

        results = self._analyze(text)
        clustered_entities = self._cluster_entities(text, results)
        anonymized_text, mapping = self._apply_clustered_anonymization(text, clustered_entities)

        if not mapping:
            return text, None

        mapping_id = None
        if self.valves.enable_persistence:
            mapping_id = self._store_mapping(
                original_text=text,
                anonymized_text=anonymized_text,
                mapping=mapping,
            )

        return anonymized_text, mapping_id

    def deanonymize_text(self, text: str, mapping_id: str) -> str:
        if not text or not mapping_id:
            return text

        mapping = self._load_mapping(mapping_id)
        if not mapping:
            return text

        restored = text
        for token, original in sorted(mapping.items(), key=lambda item: -len(item[0])):
            restored = restored.replace(token, original)
        return restored

    def supported_entities(self) -> List[str]:
        return [
            "PERSON_FR",
            "PERSON",
            "SIRET",
            "SIREN",
            "RCS",
            "NIR",
            "EMAIL_CUSTOM",
            "IBAN_CUSTOM",
            "PHONE_FR",
            "PHONE_NUMBER",
            "LOCATION",
            "DATE_TIME",
        ]

    # -------------------------
    # Détection
    # -------------------------

    def _build_structured_regex_recognizers(self) -> Dict[str, List[Tuple[re.Pattern, float]]]:
        return {
            "SIRET": [(re.compile(r"\b\d{14}\b"), 0.95)],
            "SIREN": [(re.compile(r"\b\d{9}\b"), 0.92)],
            "RCS": [
                (
                    re.compile(r"\bRCS\s+[A-ZÀ-ÿ][A-Za-zÀ-ÿ'’\- ]+\s+\d{3}\s+\d{3}\s+\d{3}\b"),
                    0.85,
                )
            ],
            "NIR": [
                (
                    re.compile(r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b"),
                    0.95,
                )
            ],
            "EMAIL_CUSTOM": [
                (
                    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
                    0.99,
                )
            ],
            "IBAN_CUSTOM": [
                (
                    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
                    0.98,
                )
            ],
            "PHONE_FR": [
                (re.compile(r"\b0[1-9](?:[ .-]?\d{2}){4}\b"), 0.90),
                (re.compile(r"\+33[ .-]?[1-9](?:[ .-]?\d{2}){4}\b"), 0.90),
            ],
        }

    def _build_person_regex_recognizers(self) -> Dict[str, List[Tuple[re.Pattern, float]]]:
        return {
            "PERSON_FR": [
                (
                    re.compile(
                        r"\b([A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]{1,30}\s+[A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]{1,30})\b"
                    ),
                    0.78,
                ),
            ]
        }

    def _setup_presidio(self) -> None:
        if AnalyzerEngine is None or RecognizerRegistry is None or PatternRecognizer is None or Pattern is None:
            return

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()

        def add(entity: str, patterns: List[Tuple[str, str, float]]) -> None:
            registry.add_recognizer(
                PatternRecognizer(
                    supported_language=self.valves.presidio_language,
                    supported_entity=entity,
                    name=entity,
                    patterns=[Pattern(name=name, regex=regex, score=score) for name, regex, score in patterns],
                )
            )

        add("SIRET", [("SIRET", r"\b\d{14}\b", 0.95)])
        add("SIREN", [("SIREN", r"\b\d{9}\b", 0.92)])
        add("RCS", [("RCS", r"\bRCS\s+[A-ZÀ-ÿ][A-Za-zÀ-ÿ'’\- ]+\s+\d{3}\s+\d{3}\s+\d{3}\b", 0.85)])
        add("NIR", [("NIR", r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b", 0.95)])
        add("EMAIL_CUSTOM", [("Email simple", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.99)])
        add("IBAN_CUSTOM", [("IBAN generic", r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", 0.98)])
        add(
            "PHONE_FR",
            [
                ("Phone FR national", r"\b0[1-9](?:[ .-]?\d{2}){4}\b", 0.90),
                ("Phone FR international", r"\+33[ .-]?[1-9](?:[ .-]?\d{2}){4}\b", 0.90),
            ],
        )
        add(
            "PERSON_FR",
            [
                (
                    "French full name strict",
                    r"\b([A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]{1,30}\s+[A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]{1,30})\b",
                    0.78,
                ),
            ],
        )

        self.registry = registry
        self.analyzer = AnalyzerEngine(registry=registry)

    def _enabled_structured_entities(self) -> List[str]:
        v = self.valves
        entities: List[str] = []
        if v.enable_siret:
            entities.append("SIRET")
        if v.enable_siren:
            entities.append("SIREN")
        if v.enable_rcs:
            entities.append("RCS")
        if v.enable_nir:
            entities.append("NIR")
        if v.enable_email:
            entities.append("EMAIL_CUSTOM")
        if v.enable_iban:
            entities.append("IBAN_CUSTOM")
        if v.enable_phone_fr:
            entities.append("PHONE_FR")
        if v.enable_phone:
            entities.append("PHONE_NUMBER")
        return entities

    def _enabled_person_entities(self) -> List[str]:
        v = self.valves
        entities: List[str] = []
        if v.enable_person_fr:
            entities.append("PERSON_FR")
        if v.enable_person:
            entities.append("PERSON")
        return entities

    def _enabled_generic_entities(self) -> List[str]:
        v = self.valves
        entities: List[str] = []
        if v.enable_location:
            entities.append("LOCATION")
        if v.enable_datetime:
            entities.append("DATE_TIME")
        return entities

    def _analyze(self, text: str) -> List[SimpleResult]:
        if not text:
            return []

        structured = self._detect_structured_entities(text)
        occupied = [(r.start, r.end) for r in structured]

        persons = self._detect_person_entities(text, occupied)
        occupied.extend((r.start, r.end) for r in persons)

        generic = self._detect_generic_entities(text, occupied)

        results = structured + persons + generic
        return self._dedupe_and_select_best(results)

    def _detect_structured_entities(self, text: str) -> List[SimpleResult]:
        entities = self._enabled_structured_entities()
        results: List[SimpleResult] = []

        for entity_type in entities:
            for pattern, score in self._structured_regex.get(entity_type, []):
                for match in pattern.finditer(text):
                    results.append(SimpleResult(entity_type, match.start(), match.end(), score))

        if self.analyzer is not None and entities:
            try:
                presidio_results = self.analyzer.analyze(
                    text=text,
                    language=self.valves.presidio_language,
                    entities=entities,
                    score_threshold=self.valves.score_threshold,
                )
                for item in presidio_results:
                    results.append(SimpleResult(item.entity_type, item.start, item.end, float(item.score)))
            except Exception:
                pass

        return self._dedupe_and_select_best(results)

    def _detect_person_entities(self, text: str, occupied_ranges: List[Tuple[int, int]]) -> List[SimpleResult]:
        entities = self._enabled_person_entities()
        results: List[SimpleResult] = []

        for entity_type in entities:
            for pattern, score in self._person_regex.get(entity_type, []):
                for match in pattern.finditer(text):
                    start, end = match.start(), match.end()
                    if self._overlaps_any(start, end, occupied_ranges):
                        continue
                    results.append(SimpleResult(entity_type, start, end, score))

        return self._dedupe_and_select_best(results)

    def _detect_generic_entities(self, text: str, occupied_ranges: List[Tuple[int, int]]) -> List[SimpleResult]:
        entities = self._enabled_generic_entities()
        results: List[SimpleResult] = []

        if self.analyzer is not None and entities:
            try:
                presidio_results = self.analyzer.analyze(
                    text=text,
                    language=self.valves.presidio_language,
                    entities=entities,
                    score_threshold=self.valves.score_threshold,
                )
                for item in presidio_results:
                    if self._overlaps_any(item.start, item.end, occupied_ranges):
                        continue
                    results.append(SimpleResult(item.entity_type, item.start, item.end, float(item.score)))
            except Exception:
                pass

        return self._dedupe_and_select_best(results)

    def _dedupe_and_select_best(self, results: List[SimpleResult]) -> List[SimpleResult]:
        if not results:
            return []

        ordered = sorted(
            results,
            key=lambda item: (
                ENTITY_PRIORITY.get(item.entity_type, 0),
                item.score,
                item.end - item.start,
            ),
            reverse=True,
        )

        selected: List[SimpleResult] = []
        for item in ordered:
            if not any(self._ranges_overlap(item.start, item.end, kept.start, kept.end) for kept in selected):
                selected.append(item)

        selected.sort(key=lambda item: (item.start, item.end))
        return selected

    def _ranges_overlap(self, a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
        return not (a_end <= b_start or a_start >= b_end)

    def _overlaps_any(self, start: int, end: int, ranges: List[Tuple[int, int]]) -> bool:
        return any(self._ranges_overlap(start, end, r_start, r_end) for r_start, r_end in ranges)

    def _cluster_entities(self, text: str, results: List[SimpleResult]) -> List[ClusteredEntity]:
        window = self.valves.person_window_chars
        anchors = [r for r in results if r.entity_type in PERSON_TYPES]
        others = [r for r in results if r.entity_type not in PERSON_TYPES]
        anchors.sort(key=lambda item: item.start)

        clustered: List[ClusteredEntity] = []

        for idx, anchor in enumerate(anchors, start=1):
            clustered.append(
                ClusteredEntity(
                    entity_type=anchor.entity_type,
                    start=anchor.start,
                    end=anchor.end,
                    score=anchor.score,
                    text=text[anchor.start:anchor.end],
                    person_id=idx,
                )
            )

        for item in others:
            best_person_id: Optional[int] = None

            previous_anchors = [
                (idx, anchor)
                for idx, anchor in enumerate(anchors, start=1)
                if anchor.end <= item.start
            ]
            next_anchors = [
                (idx, anchor)
                for idx, anchor in enumerate(anchors, start=1)
                if anchor.start >= item.end
            ]

            if previous_anchors:
                idx, anchor = previous_anchors[-1]
                dist = item.start - anchor.end
                if dist <= window:
                    best_person_id = idx
            elif next_anchors:
                idx, anchor = next_anchors[0]
                dist = anchor.start - item.end
                if dist <= window:
                    best_person_id = idx

            clustered.append(
                ClusteredEntity(
                    entity_type=item.entity_type,
                    start=item.start,
                    end=item.end,
                    score=item.score,
                    text=text[item.start:item.end],
                    person_id=best_person_id,
                )
            )

        clustered.sort(key=lambda item: (item.start, item.end))
        return clustered

    def _apply_clustered_anonymization(
        self,
        text: str,
        entities: List[ClusteredEntity],
    ) -> Tuple[str, Dict[str, str]]:
        if not entities:
            return text, {}

        mapping: Dict[str, str] = {}
        result_parts: List[str] = []
        last_idx = 0
        type_counters: Dict[str, int] = {}
        person_type_counters: Dict[int, Dict[str, int]] = {}

        for entity in entities:
            if entity.start < last_idx:
                continue

            if entity.start > last_idx:
                result_parts.append(text[last_idx:entity.start])

            subtype = self._normalize_subtype(entity.entity_type)

            if entity.person_id is not None:
                person_type_counters.setdefault(entity.person_id, {})
                person_type_counters[entity.person_id].setdefault(subtype, 0)
                person_type_counters[entity.person_id][subtype] += 1
                idx = person_type_counters[entity.person_id][subtype]
                token = f"[PERSON_{entity.person_id}_{subtype}_{idx}]"
            else:
                type_counters.setdefault(subtype, 0)
                type_counters[subtype] += 1
                idx = type_counters[subtype]
                token = f"[{subtype}_{idx}]"

            mapping[token] = entity.text
            result_parts.append(token)
            last_idx = entity.end

        if last_idx < len(text):
            result_parts.append(text[last_idx:])

        return "".join(result_parts), mapping

    def _normalize_subtype(self, entity_type: str) -> str:
        if entity_type in PERSON_TYPES:
            return "NAME"
        if entity_type == "EMAIL_CUSTOM":
            return "EMAIL"
        if entity_type == "IBAN_CUSTOM":
            return "IBAN"
        if entity_type in {"PHONE_FR", "PHONE_NUMBER"}:
            return "PHONE"
        if entity_type == "DATE_TIME":
            return "DATE"
        return entity_type

    # -------------------------
    # SQLite
    # -------------------------

    def _init_db(self) -> None:
        db_path = Path(self.valves.sqlite_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._db_lock, sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    mapping_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    anonymized_text TEXT,
                    original_text TEXT,
                    mapping_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _original_text_column_requires_value(self) -> bool:
        with self._db_lock, sqlite3.connect(self.valves.sqlite_path) as conn:
            rows = conn.execute("PRAGMA table_info(mappings)").fetchall()

        for row in rows:
            if row[1] == "original_text":
                return bool(row[3])
        return False

    def _store_mapping(self, original_text: str, anonymized_text: str, mapping: Dict[str, str]) -> str:
        mapping_id = str(uuid.uuid4())
        now = int(time.time())

        if self.valves.persist_original_text:
            original_to_store = original_text
        else:
            original_to_store = None
            if self._original_text_column_requires_value():
                original_to_store = ""

        with self._db_lock, sqlite3.connect(self.valves.sqlite_path) as conn:
            conn.execute(
                """
                INSERT INTO mappings (mapping_id, created_at, anonymized_text, original_text, mapping_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    mapping_id,
                    now,
                    anonymized_text,
                    original_to_store,
                    json.dumps(mapping, ensure_ascii=False),
                ),
            )
            conn.execute(
                "DELETE FROM mappings WHERE created_at < ?",
                (now - self.valves.mapping_ttl_hours * 3600,),
            )
            conn.commit()

        return mapping_id

    def _load_mapping(self, mapping_id: str) -> Dict[str, str]:
        with self._db_lock, sqlite3.connect(self.valves.sqlite_path) as conn:
            row = conn.execute(
                "SELECT mapping_json FROM mappings WHERE mapping_id = ?",
                (mapping_id,),
            ).fetchone()

        return json.loads(row[0]) if row else {}
