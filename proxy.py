from __future__ import annotations

from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union
import json
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from anonymizer_axiorhub import Tools


logger = logging.getLogger("anonymizer_proxy")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

OPEN_WEBUI_BASE_URL = os.getenv("OPEN_WEBUI_BASE_URL", "http://open-webui:8080").rstrip("/")
DEFAULT_MODEL = os.getenv("OPEN_WEBUI_MODEL", "meta-llama/llama-3.1-8b-instruct")
REQUEST_TIMEOUT = float(os.getenv("PROXY_TIMEOUT_SECONDS", "120"))
ANONYMIZE_SYSTEM_MESSAGES = os.getenv("ANONYMIZE_SYSTEM_MESSAGES", "false").lower() == "true"
DEANONYMIZE_ASSISTANT_MESSAGES = os.getenv("DEANONYMIZE_ASSISTANT_MESSAGES", "true").lower() == "true"

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}


app = FastAPI(title="PII Anonymization Proxy", version="1.0.0")
anonymizer = Tools()


ContentPart = Dict[str, Any]
MessageContent = Union[str, List[ContentPart], None]


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: MessageContent = None
    name: Optional[str] = None
    tool_call_id: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: Optional[str] = None
    messages: List[ChatMessage] = Field(default_factory=list)
    stream: bool = False


class DeanonymizeRequest(BaseModel):
    text: str
    mapping_id: str


def _sanitize_outgoing_headers(headers: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in headers:
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        out[key] = value
    return out


def _sanitize_response_headers(headers: httpx.Headers) -> Dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def _should_anonymize_role(role: str) -> bool:
    if role == "user":
        return True
    if role == "system":
        return ANONYMIZE_SYSTEM_MESSAGES
    return False


def _anonymize_text(text: str) -> Tuple[str, Optional[str]]:
    cleaned = text or ""
    cleaned = cleaned.strip()
    if not cleaned:
        return text, None
    anonymized_text, mapping_id = anonymizer.anonymize_text_with_mapping(cleaned)
    return anonymized_text, mapping_id


def _anonymize_content(content: MessageContent) -> Tuple[MessageContent, List[str]]:
    mapping_ids: List[str] = []

    if isinstance(content, str):
        anonymized, mapping_id = _anonymize_text(content)
        if mapping_id:
            mapping_ids.append(mapping_id)
        return anonymized, mapping_ids

    if isinstance(content, list):
        anonymized_parts: List[ContentPart] = []
        for part in content:
            if not isinstance(part, dict):
                anonymized_parts.append(part)
                continue

            if part.get("type") == "text" and isinstance(part.get("text"), str):
                anonymized_text, mapping_id = _anonymize_text(part["text"])
                new_part = dict(part)
                new_part["text"] = anonymized_text
                anonymized_parts.append(new_part)
                if mapping_id:
                    mapping_ids.append(mapping_id)
            else:
                anonymized_parts.append(part)

        return anonymized_parts, mapping_ids

    return content, mapping_ids


def _anonymize_messages(messages: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    anonymized_messages: List[Dict[str, Any]] = []
    mapping_ids: List[str] = []

    for message in messages:
        cloned = dict(message)
        role = str(cloned.get("role", ""))
        if _should_anonymize_role(role):
            new_content, ids = _anonymize_content(cloned.get("content"))
            cloned["content"] = new_content
            mapping_ids.extend(ids)
        anonymized_messages.append(cloned)

    return anonymized_messages, mapping_ids


def _deanonymize_text_with_many_mappings(text: str, mapping_ids: List[str]) -> str:
    if not text or not mapping_ids or not DEANONYMIZE_ASSISTANT_MESSAGES:
        return text

    restored = text
    for mapping_id in mapping_ids:
        restored = anonymizer.deanonymize_text(restored, mapping_id)
    return restored


def _deanonymize_content(content: Any, mapping_ids: List[str]) -> Any:
    if isinstance(content, str):
        return _deanonymize_text_with_many_mappings(content, mapping_ids)
    if isinstance(content, list):
        new_parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                new_part = dict(part)
                new_part["text"] = _deanonymize_text_with_many_mappings(new_part["text"], mapping_ids)
                new_parts.append(new_part)
            else:
                new_parts.append(part)
        return new_parts
    return content


def _deanonymize_chat_completion_payload(payload: Dict[str, Any], mapping_ids: List[str]) -> Dict[str, Any]:
    if not mapping_ids or not DEANONYMIZE_ASSISTANT_MESSAGES:
        return payload

    data = json.loads(json.dumps(payload))
    for choice in data.get("choices", []):
        message = choice.get("message")
        if isinstance(message, dict):
            message["content"] = _deanonymize_content(message.get("content"), mapping_ids)
    return data


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest, request: Request) -> Response:
    if not req.messages:
        raise HTTPException(status_code=400, detail="messages est obligatoire")
    if req.stream:
        raise HTTPException(
            status_code=400,
            detail="Le streaming SSE n'est pas encore supporté par cette route d'anonymisation. Utilise stream=false.",
        )

    payload = req.model_dump(mode="json")
    payload["model"] = payload.get("model") or DEFAULT_MODEL
    payload["messages"], mapping_ids = _anonymize_messages(payload["messages"])

    headers = _sanitize_outgoing_headers(request.headers.items())

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            upstream = await client.post(
                f"{OPEN_WEBUI_BASE_URL}/api/chat/completions",
                json=payload,
                headers=headers,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Erreur vers Open WebUI: {exc}") from exc

    if upstream.status_code >= 400:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=_sanitize_response_headers(upstream.headers),
            media_type=upstream.headers.get("content-type"),
        )

    try:
        response_payload = upstream.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Réponse JSON invalide depuis Open WebUI") from exc

    response_payload = _deanonymize_chat_completion_payload(response_payload, mapping_ids)
    response_headers = _sanitize_response_headers(upstream.headers)
    if mapping_ids:
        response_headers["X-Anonymizer-Mapping-Ids"] = ",".join(mapping_ids)

    return JSONResponse(
        content=response_payload,
        status_code=upstream.status_code,
        headers=response_headers,
    )


@app.post("/deanonymize")
async def deanonymize(req: DeanonymizeRequest) -> Dict[str, str]:
    return {
        "text": anonymizer.deanonymize_text(req.text, req.mapping_id),
        "mapping_id": req.mapping_id,
    }


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy_all(request: Request, full_path: str) -> Response:
    if full_path in {"healthz", "v1/chat/completions", "deanonymize"}:
        raise HTTPException(status_code=404, detail="Not found")

    target_url = f"{OPEN_WEBUI_BASE_URL}/{full_path}"
    headers = _sanitize_outgoing_headers(request.headers.items())
    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            upstream = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=request.query_params,
                content=body,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Erreur vers Open WebUI: {exc}") from exc

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_sanitize_response_headers(upstream.headers),
        media_type=upstream.headers.get("content-type"),
    )
