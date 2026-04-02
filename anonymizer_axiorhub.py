"""
title: Anonymizer-Axiorhub
author: OpenAI
version: 2.0.0
license: MIT
description: Outil Open WebUI pour anonymiser/désanonymiser les prompts avec mapping persistant SQLite,
             recognizers FR custom (NIR, SIRET, SIREN, RCS, EMAIL, IBAN, PHONE_FR) et fallback robuste.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Dict, List, Optional, Tuple
import json
import os
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
        RecognizerResult,
    )
except Exception:  # pragma: no cover
    AnalyzerEngine = None  # type: ignore[assignment]
    Pattern = None  # type: ignore[assignment]
    PatternRecognizer = None  # type: ignore[assignment]
    RecognizerRegistry = None  # type: ignore[assignment]
    RecognizerResult = None  # type: ignore[assignment]


TOKEN_RE = re.compile(r"\[(?:PERSON_\d+_)?[A-Z_]+_\d+\]")


class Valves(BaseModel):
    sqlite_path: str = Field(
        default="/data/pii_map.sqlite",
        description="Chemin SQLite persistant.",
    )
    mapping_ttl_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="TTL des mappings en heures.",
    )
    score_threshold: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Seuil de détection Presidio.",
    )
    enable_persistence: bool = Field(
        default=True,
        description="Persister les mappings en SQLite.",
    )
    persist_original_text: bool = Field(
        default=False,
        description="Stocker le texte original. Désactivé par défaut pour limiter l'exposition.",
    )

    # Recognizers FR custom
    enable_person_fr: bool = True
    enable_siret: bool = True
    enable_siren: bool = True
    enable_rcs: bool = True
    enable_nir: bool = True
    enable_email: bool = True
    enable_iban: bool = True
    enable_phone_fr: bool = True

    # Entités Presidio génériques. Désactivées par défaut car souvent peu fiables sans modèle NLP configuré.
    enable_person: bool = False
    enable_location: bool = False
    enable_datetime: bool = False
    enable_phone: bool = False

    person_window_chars: int = Field(
        default=120,
        ge=20,
        le=1000,
        description="Fenêtre de rattachement des PII à une personne.",
    )
    presidio_language: str = Field(
        default="en",
        description="Langue Presidio. 'en' tant que les recognizers custom sont définis pour cette langue.",
    )


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
    def __init__(self) -> None:
        self.valves = Valves()
        self._db_lock = RLock()
        self._regex_recognizers = self._build_regex_recognizers()
        self.registry = None
        self.analyzer = None
        self._setup_presidio()
        self._init_db()

    # -------------------------
    # API Open WebUI publique
    # -------------------------

    async def anonymize_prompt(self, text: str) -> str:
        """Anonymise le texte et ajoute un MAPPING_ID si la persistance est activée.

        Cette méthode est pratique pour un usage manuel depuis Open WebUI.
        Pour un proxy, préfère `anonymize_text_with_mapping` pour éviter d'injecter
        le mapping ID dans le prompt envoyé au modèle.
        """
        anonymized_text, mapping_id = self.anonymize_text_with_mapping(text)
        if mapping_id:
            return f"{anonymized_text}\n\n[MAPPING_ID={mapping_id}]"
        return anonymized_text

    async def deanonymize_prompt(self, text: str, mapping_id: str) -> str:
        if not text or not mapping_id:
            return text
        return self.deanonymize_text(text, mapping_id)

    # -------------------------
    # API interne utile au proxy
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
            "SIRET",
            "SIREN",
            "RCS",
            "NIR",
            "EMAIL_CUSTOM",
            "IBAN_CUSTOM",
            "PHONE_FR",
            "PERSON",
            "LOCATION",
            "DATE_TIME",
            "PHONE_NUMBER",
        ]

    # -------------------------
    # Détection / anonymisation
    # -------------------------

    def _build_regex_recognizers(self) -> Dict[str, List[Tuple[re.Pattern, float]]]:
        return {
            "PERSON_FR": [
                (
                    re.compile(
                        r"\b([A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]+(?:\s+[A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]+){1,3})\b"
                    ),
                    0.72,
                ),
                (
                    re.compile(
                        r"\b([A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ]{2,}(?:\s+[A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ]{2,}){1,3})\b"
                    ),
                    0.55,
                ),
            ],
            "SIRET": [(re.compile(r"\b\d{14}\b"), 0.95)],
            "SIREN": [(re.compile(r"\b\d{9}\b"), 0.92)],
            "RCS": [
                (
                    re.compile(
                        r"\bRCS\s+[A-ZÀ-ÿ][A-Za-zÀ-ÿ'’\- ]+\s+\d{3}\s+\d{3}\s+\d{3}\b"
                    ),
                    0.80,
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
                    0.90,
                )
            ],
            "IBAN_CUSTOM": [
                (
                    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
                    0.90,
                )
            ],
            "PHONE_FR": [
                (re.compile(r"\b0[1-9](?:[ .-]?\d{2}){4}\b"), 0.90),
                (re.compile(r"\+33[ .-]?[1-9](?:[ .-]?\d{2}){4}\b"), 0.90),
            ],
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

        add(
            "PERSON_FR",
            [
                (
                    "French full name",
                    r"\b([A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]+(?:\s+[A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ][a-zà-ÿ'’\-]+){1,3})\b",
                    0.72,
                ),
                (
                    "French uppercase name",
                    r"\b([A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ]{2,}(?:\s+[A-ZÉÈÀÂÊÎÔÛÄËÏÖÜÇ]{2,}){1,3})\b",
                    0.55,
                ),
            ],
        )
        add("SIRET", [("SIRET", r"\b\d{14}\b", 0.95)])
        add("SIREN", [("SIREN", r"\b\d{9}\b", 0.92)])
        add(
            "RCS",
            [("RCS", r"\bRCS\s+[A-ZÀ-ÿ][A-Za-zÀ-ÿ'’\- ]+\s+\d{3}\s+\d{3}\s+\d{3}\b", 0.80)],
        )
        add("NIR", [("NIR", r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b", 0.95)])
        add(
            "EMAIL_CUSTOM",
            [("Email simple", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.90)],
        )
        add("IBAN_CUSTOM", [("IBAN generic", r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", 0.90)])
        add(
            "PHONE_FR",
            [
                ("Phone FR national", r"\b0[1-9](?:[ .-]?\d{2}){4}\b", 0.90),
                ("Phone FR international", r"\+33[ .-]?[1-9](?:[ .-]?\d{2}){4}\b", 0.90),
            ],
        )

        self.registry = registry
        self.analyzer = AnalyzerEngine(registry=registry)

    def _enabled_entities(self) -> List[str]:
        v = self.valves
        entities: List[str] = []
        if v.enable_person_fr:
            entities.append("PERSON_FR")
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
        if v.enable_person:
            entities.append("PERSON")
        if v.enable_location:
            entities.append("LOCATION")
        if v.enable_datetime:
            entities.append("DATE_TIME")
        if v.enable_phone:
            entities.append("PHONE_NUMBER")
        return entities

    def _analyze(self, text: str) -> List[SimpleResult]:
        entities = self._enabled_entities()
        if not entities or not text:
            return []

        results: List[SimpleResult] = []

        # 1) Recognizers regex locaux, toujours dispo
        for entity_type in entities:
            for pattern, score in self._regex_recognizers.get(entity_type, []):
                for match in pattern.finditer(text):
                    results.append(
                        SimpleResult(
                            entity_type=entity_type,
                            start=match.start(),
                            end=match.end(),
                            score=score,
                        )
                    )

        # 2) Presidio en complément si dispo
        if self.analyzer is not None:
            try:
                presidio_results = self.analyzer.analyze(
                    text=text,
                    language=self.valves.presidio_language,
                    entities=entities,
                    score_threshold=self.valves.score_threshold,
                )
                for item in presidio_results:
                    results.append(
                        SimpleResult(
                            entity_type=item.entity_type,
                            start=item.start,
                            end=item.end,
                            score=float(item.score),
                        )
                    )
            except Exception:
                pass

        return self._merge_overlapping_results(results)

    def _cluster_entities(self, text: str, results: List[SimpleResult]) -> List[ClusteredEntity]:
        window = self.valves.person_window_chars
        anchors = [r for r in results if r.entity_type in ("PERSON", "PERSON_FR")]
        others = [r for r in results if r.entity_type not in ("PERSON", "PERSON_FR")]
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
            best_dist: Optional[int] = None
            for idx, anchor in enumerate(anchors, start=1):
                dist = max(0, max(anchor.start, item.start) - min(anchor.end, item.end))
                if best_dist is None or dist < best_dist:
                    best_dist = dist
                    best_person_id = idx
            person_id = best_person_id if best_dist is not None and best_dist <= window else None
            clustered.append(
                ClusteredEntity(
                    entity_type=item.entity_type,
                    start=item.start,
                    end=item.end,
                    score=item.score,
                    text=text[item.start:item.end],
                    person_id=person_id,
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
        if entity_type in {"PERSON", "PERSON_FR"}:
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
    # Persistence SQLite
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

    def _store_mapping(self, original_text: str, anonymized_text: str, mapping: Dict[str, str]) -> str:
        mapping_id = str(uuid.uuid4())
        now = int(time.time())
        original_to_store = original_text if self.valves.persist_original_text else None

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

    # -------------------------
    # Utilitaires
    # -------------------------

    def _merge_overlapping_results(self, results: List[SimpleResult]) -> List[SimpleResult]:
        if not results:
            return []

        ordered = sorted(
            results,
            key=lambda item: (item.start, -(item.end - item.start), -item.score),
        )
        merged: List[SimpleResult] = []
        for item in ordered:
            if merged and item.start < merged[-1].end:
                continue
            merged.append(item)
        return merged
