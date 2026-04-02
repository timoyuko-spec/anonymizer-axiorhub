import uuid
from pathlib import Path

from anonymizer_axiorhub import Tools, Valves

def _make_tools(tmp_path: Path) -> Tools:
    return Tools(
        Valves(
            sqlite_path=str(tmp_path / f"pii_map_{uuid.uuid4().hex}.sqlite"),
            enable_persistence=True,
            persist_original_text=False,
        )
    )


def _anon(tools: Tools, text: str):
    anonymized, mapping_id = tools.anonymize_text_with_mapping(text)
    assert mapping_id, "Un mapping_id devrait être généré quand des PII sont détectées"
    return anonymized, mapping_id


def test_email_and_iban_and_name_are_anonymized(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = (
        "Bonjour, je suis Jean Dupont, mon email est jean.dupont@example.com "
        "et mon IBAN est FR7612345678901234567890123"
    )

    anonymized, mapping_id = _anon(tools, text)

    assert "[PERSON_1_NAME_1]" in anonymized
    assert "[PERSON_1_EMAIL_1]" in anonymized
    assert "[PERSON_1_IBAN_1]" in anonymized
    assert "Jean Dupont" not in anonymized
    assert "jean.dupont@example.com" not in anonymized
    assert "FR7612345678901234567890123" not in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_two_people_two_emails_are_separated(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = (
        "Jean Dupont : jean.dupont@example.com\n"
        "Marie Martin : marie.martin@example.com"
    )

    anonymized, mapping_id = _anon(tools, text)

    assert "[PERSON_1_NAME_1]" in anonymized
    assert "[PERSON_1_EMAIL_1]" in anonymized
    assert "[PERSON_2_NAME_1]" in anonymized
    assert "[PERSON_2_EMAIL_1]" in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_phone_fr_is_anonymized(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = "Je m'appelle Jean Dupont, mon téléphone est 06 12 34 56 78."

    anonymized, mapping_id = _anon(tools, text)

    assert "[PHONE_" in anonymized or "[PERSON_1_PHONE_1]" in anonymized
    assert "06 12 34 56 78" not in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_phone_fr_international_is_anonymized(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = "Mon numéro est +33 6 12 34 56 78."

    anonymized, mapping_id = _anon(tools, text)

    assert "[PHONE_" in anonymized
    assert "+33 6 12 34 56 78" not in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_siren_and_siret_are_anonymized(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = "Mon SIREN est 123456789 et mon SIRET est 12345678901234."

    anonymized, mapping_id = _anon(tools, text)

    assert "[SIREN_1]" in anonymized or "[PERSON_1_SIREN_1]" in anonymized
    assert "[SIRET_1]" in anonymized or "[PERSON_1_SIRET_1]" in anonymized
    assert "12345678901234" not in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_nir_is_anonymized(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = "Mon numéro de sécurité sociale est 1 84 12 76 451 089 46."

    anonymized, mapping_id = _anon(tools, text)

    assert "[NIR_1]" in anonymized or "[PERSON_1_NIR_1]" in anonymized
    assert "1 84 12 76 451 089 46" not in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_rcs_is_anonymized(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = "La société est immatriculée sous RCS Paris 123 456 789."

    anonymized, mapping_id = _anon(tools, text)

    assert "[RCS_1]" in anonymized or "[PERSON_1_RCS_1]" in anonymized
    assert "RCS Paris 123 456 789" not in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_text_without_pii_is_left_unchanged(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = "Bonjour, pouvez-vous résumer ce document juridique ?"

    anonymized, mapping_id = tools.anonymize_text_with_mapping(text)

    assert anonymized == text
    assert mapping_id is None


def test_email_is_not_broken_into_fake_person_tokens(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = "Mon email est jean.dupont@example.com."

    anonymized, mapping_id = _anon(tools, text)

    assert "example.[PERSON" not in anonymized
    assert ".dupont@" not in anonymized
    assert "[EMAIL_1]" in anonymized or "[PERSON_1_EMAIL_1]" in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_multiple_pii_same_person_are_grouped(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = (
        "Jean Dupont, né le 12/03/1985, a pour email jean.dupont@example.com "
        "et pour IBAN FR7612345678901234567890123."
    )

    anonymized, mapping_id = _anon(tools, text)

    assert "[PERSON_1_NAME_1]" in anonymized
    assert "[PERSON_1_EMAIL_1]" in anonymized
    assert "[PERSON_1_IBAN_1]" in anonymized

    restored = tools.deanonymize_text(anonymized, mapping_id)
    assert restored == text


def test_deanonymization_restores_original_text_exactly(tmp_path: Path):
    tools = _make_tools(tmp_path)
    text = (
        "Jean Dupont\n"
        "Email: jean.dupont@example.com\n"
        "Téléphone: 06 12 34 56 78\n"
        "IBAN: FR7612345678901234567890123"
    )

    anonymized, mapping_id = _anon(tools, text)
    restored = tools.deanonymize_text(anonymized, mapping_id)

    assert restored == text
