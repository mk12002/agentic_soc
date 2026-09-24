"""
Multi-language phishing detection for the content agent.

The content agent's ``PHISHING_PATTERNS`` are English-only, so a Spanish, French,
German, Portuguese, or Italian phishing lure (``verifique su cuenta``,
``vérifiez votre compte``, ``Konto bestätigen``) passes the lexical layer
untouched — a cheap and common evasion against English-tuned filters.

This module is **dependency-free** (no ``langdetect``/``lingua``). It carries
accurate, native phishing keyword sets per language and a lightweight
stopword-based language hint. The strongest signal is *cross-language evasion*:
phishing-category language present in a non-English language (optionally with no
English equivalent), which legitimate English-org mail almost never contains.

Everything reported is a literal keyword the text actually contains, so it feeds
the grounded-evidence layer faithfully.
"""

from __future__ import annotations

import re
from typing import Any

# Native phishing keywords per language and category. Accents are significant and
# match against lower-cased text. Only distinctive multi-character terms are used
# to keep false positives low.
_PHISHING_KEYWORDS: dict[str, dict[str, list[str]]] = {
    "es": {
        "urgency": ["urgente", "inmediatamente", "acción requerida", "cuenta suspendida", "verifique", "confirme"],
        "credential": ["contraseña", "iniciar sesión", "verificar cuenta", "credenciales", "su identidad"],
        "financial": ["factura", "pago", "transferencia", "reembolso", "fondos"],
    },
    "fr": {
        "urgency": ["urgent", "immédiatement", "action requise", "compte suspendu", "vérifiez", "confirmez"],
        "credential": ["mot de passe", "connexion", "vérifier le compte", "identifiants", "votre identité"],
        "financial": ["facture", "paiement", "virement", "remboursement", "fonds"],
    },
    "de": {
        "urgency": ["dringend", "sofort", "erforderlich", "konto gesperrt", "bestätigen", "überprüfen"],
        "credential": ["passwort", "anmelden", "konto verifizieren", "anmeldedaten", "ihre identität"],
        "financial": ["rechnung", "zahlung", "überweisung", "rückerstattung", "geldmittel"],
    },
    "pt": {
        "urgency": ["urgente", "imediatamente", "ação necessária", "conta suspensa", "verifique", "confirme"],
        "credential": ["senha", "iniciar sessão", "verificar conta", "credenciais", "sua identidade"],
        "financial": ["fatura", "pagamento", "transferência", "reembolso", "fundos"],
    },
    "it": {
        "urgency": ["urgente", "immediatamente", "azione richiesta", "account sospeso", "verifica", "conferma"],
        "credential": ["password", "accedi", "verifica account", "credenziali", "la tua identità"],
        "financial": ["fattura", "pagamento", "bonifico", "rimborso", "fondi"],
    },
}

# Common function words per language for a coarse language hint. English included
# so we can tell "non-English body" from "English body with a stray foreign word".
_STOPWORDS: dict[str, set[str]] = {
    "en": {"the", "and", "you", "your", "to", "for", "is", "of", "please", "we", "this", "account"},
    "es": {"de", "la", "que", "el", "en", "los", "se", "su", "para", "con", "una", "por"},
    "fr": {"le", "la", "les", "de", "et", "un", "une", "est", "vous", "pour", "votre", "avec"},
    "de": {"der", "die", "das", "und", "ist", "sie", "ein", "eine", "ihre", "für", "mit", "nicht"},
    "pt": {"de", "que", "do", "da", "em", "para", "com", "uma", "os", "seu", "sua", "não"},
    "it": {"di", "che", "il", "la", "un", "una", "per", "con", "sono", "vostro", "della", "non"},
}

_LANG_NAMES = {"es": "Spanish", "fr": "French", "de": "German", "pt": "Portuguese", "it": "Italian", "en": "English"}

_WORD_RE = re.compile(r"\b[\wà-öø-ÿ]+\b", re.UNICODE)


def detect_language(text: str) -> str:
    """Best-effort language hint from function-word frequency.

    Returns a language code, or ``"unknown"`` when there is too little signal.
    This is a coarse heuristic, not a full classifier — it only needs to
    distinguish "predominantly English" from a small set of European languages.
    """
    tokens = _WORD_RE.findall((text or "").lower())
    if len(tokens) < 4:
        return "unknown"
    token_set = set(tokens)
    scores = {lang: len(token_set & words) for lang, words in _STOPWORDS.items()}
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] >= 2 else "unknown"


def _match_keywords(text: str, keywords: list[str]) -> list[str]:
    hits: list[str] = []
    for kw in keywords:
        # Word-boundary match for single tokens; substring for multi-word phrases.
        if " " in kw:
            if kw in text:
                hits.append(kw)
        elif re.search(rf"\b{re.escape(kw)}\b", text, re.UNICODE):
            hits.append(kw)
    return hits


def analyze_multilingual(text: str) -> dict[str, Any]:
    """Detect non-English phishing-category language and cross-language evasion.

    ``text`` should already be lower-cased (the content agent lowercases the
    combined subject+body before calling). Returns indicators, a bounded risk
    contribution, the detected language hint, and the per-category hits.
    """
    lowered = (text or "").lower()
    indicators: list[str] = []
    risk = 0.0
    per_language_hits: dict[str, dict[str, list[str]]] = {}

    for lang, categories in _PHISHING_KEYWORDS.items():
        cat_hits: dict[str, list[str]] = {}
        for category, keywords in categories.items():
            hits = _match_keywords(lowered, keywords)
            if hits:
                cat_hits[category] = hits
        if not cat_hits:
            continue
        per_language_hits[lang] = cat_hits

        for category, hits in cat_hits.items():
            sample = ",".join(hits[:3])
            indicators.append(f"multilingual_{category}_signals:{lang}:{sample}")
            if category == "financial":
                risk += min(0.5, 0.2 * len(hits))
            elif category == "urgency":
                risk += min(0.45, 0.15 * len(hits))
            else:  # credential
                risk += min(0.35, 0.15 * len(hits))

        # Classic BEC pattern expressed in a non-English language.
        if "financial" in cat_hits and "urgency" in cat_hits:
            risk += 0.25
            indicators.append(f"multilingual_bec_pattern:{lang}")

    language = detect_language(lowered)

    if per_language_hits:
        langs = sorted(per_language_hits.keys())
        # Cross-language evasion: the body's own language hint is non-English, or a
        # foreign phishing lure is embedded — both indicate filter-evasion intent.
        if language in per_language_hits or language not in ("en", "unknown"):
            indicators.append(f"cross_language_phishing:{','.join(langs)}")
            risk += 0.15

    return {
        "language": language,
        "language_name": _LANG_NAMES.get(language, "Unknown"),
        "hits": per_language_hits,
        "indicators": indicators,
        "risk_contribution": round(min(risk, 0.85), 4),
    }
