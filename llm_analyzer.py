"""
llm_analyzer.py
Multi-provider LLM: Ollama (lokal), OpenAI (ChatGPT), Anthropic (Claude), Google Gemini.
Semua lewat httpx langsung (tanpa SDK) agar image tetap ringan.

- LLM_PROVIDERS="ollama,gemini,openai,anthropic" => urutan prioritas + fallback otomatis.
- Provider cloud: log di-redact (password/token/email/API key) sebelum keluar jaringan.
- Output model divalidasi; output LLM tidak pernah dipercaya mentah.
"""
from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Mapping

import httpx
import orjson

log = logging.getLogger("llm")

VERDICTS = {"true_positive", "suspicious", "false_positive", "benign", "needs_investigation"}
LEVELS = {"low", "medium", "high", "critical"}
RETRY_STATUS = {429, 500, 502, 503, 504}

# ------------------------------------------------------------------ Redaction
_REDACT = [
    (re.compile(r"(?i)bearer\s+[a-z0-9._~+/\-]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization)\b(\\?\"?\s*[:=]\s*\\?\"?)([^\s\\\",;&]+)"),
     r"\1\2[REDACTED]"),
    (re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+"), "[EMAIL]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[AWS_KEY]"),
    (re.compile(r"\b(?:sk|pk|ghp|xox[abp])[-_][A-Za-z0-9_\-]{20,}\b"), "[API_KEY]"),
]


def redact(text: str) -> str:
    for pat, repl in _REDACT:
        text = pat.sub(repl, text)
    return text


# ----------------------------------------------------------------- Normalisasi
def _s(v: Any, n: int) -> str:
    return str(v)[:n]


def _list(v: Any, n_items: int = 10, n_chars: int = 300) -> list[str]:
    return [_s(x, n_chars) for x in v[:n_items]] if isinstance(v, list) else []


def _extract_json(text: str) -> dict:
    t = text.strip()
    try:
        obj = orjson.loads(t)
    except Exception:
        i, j = t.find("{"), t.rfind("}")  # toleransi ```json ... ``` / teks pembuka
        if i == -1 or j <= i:
            raise ValueError("tidak ada JSON")
        obj = orjson.loads(t[i:j + 1])
    if not isinstance(obj, dict):
        raise ValueError("bukan objek JSON")
    return obj


def normalize(log_uuid: str, content: str) -> dict:
    try:
        obj = _extract_json(content)
    except Exception:
        return {"log_id": log_uuid, "verdict": "needs_investigation", "confidence": 0.0,
                "summary": _s(content, 2000), "parse_warning": True,
                "reasoning": [], "mitre_techniques": [], "recommended_actions": []}
    try:
        conf = max(0.0, min(1.0, float(obj.get("confidence", 0.0))))
    except (TypeError, ValueError):
        conf = 0.0
    verdict, level = obj.get("verdict"), obj.get("severity_assessment")
    return {
        "log_id": log_uuid,  # paksa ID asli, abaikan ID dari model
        "verdict": verdict if verdict in VERDICTS else "needs_investigation",
        "confidence": conf,
        "severity_assessment": level if level in LEVELS else "medium",
        "summary": _s(obj.get("summary", ""), 2000),
        "reasoning": _list(obj.get("reasoning")),
        "mitre_techniques": _list(obj.get("mitre_techniques"), 10, 100),
        "recommended_actions": _list(obj.get("recommended_actions")),
    }


def describe_error(exc: Exception) -> str:
    """Hanya tipe + status code; jangan log pesan (bisa memuat URL/key)."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP{exc.response.status_code}"
    if getattr(exc, "public_message", None):
        return str(exc.public_message)[:200]
    return type(exc).__name__


# ------------------------------------------------------------------ Providers
class BaseAnalyzer(ABC):
    name = "base"
    external = False  # True => data keluar ke pihak ketiga (aktifkan redaction)

    def __init__(self, model: str, system_prompt: str, timeout_s: float,
                 mask: bool = True, max_log_chars: int = 6000):
        self.model = model
        self.system_prompt = system_prompt
        self.mask = mask
        self.max_log_chars = max_log_chars
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s, connect=5.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10))

    @abstractmethod
    async def _complete(self, system: str, user: str) -> str: ...

    async def analyze(self, log_uuid: str, doc: dict) -> dict:
        log_json = orjson.dumps(doc).decode()
        if self.external and self.mask:
            log_json = redact(log_json)
        user_msg = (
            f"LOG_ID: {log_uuid}\n<LOG_DATA>\n{log_json[: self.max_log_chars]}\n</LOG_DATA>\n"
            "Analisis log di atas dan balas HANYA dengan JSON sesuai skema.")
        return normalize(log_uuid, await self._complete(self.system_prompt, user_msg))

    async def _post(self, url: str, body: dict, headers: dict | None = None) -> dict:
        for attempt in range(2):  # 1x retry untuk 429/5xx
            r = await self._client.post(url, json=body, headers=headers)
            if r.status_code in RETRY_STATUS and attempt == 0:
                await asyncio.sleep(2)
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("unreachable")

    async def aclose(self) -> None:
        await self._client.aclose()


class OllamaAnalyzer(BaseAnalyzer):
    name = "ollama"

    def __init__(self, base_url: str, keep_alive: str = "30m", **kw):
        super().__init__(**kw)
        self.url = base_url.rstrip("/") + "/api/chat"
        self.keep_alive = keep_alive

    async def _complete(self, system: str, user: str) -> str:
        data = await self._post(self.url, {
            "model": self.model, "stream": False, "format": "json",
            "keep_alive": self.keep_alive, "options": {"temperature": 0.1},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]})
        return data["message"]["content"]


class OpenAIAnalyzer(BaseAnalyzer):
    """ChatGPT. base_url bisa diganti untuk endpoint yang kompatibel OpenAI."""
    name, external = "openai", True

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1", **kw):
        super().__init__(**kw)
        self.url = base_url.rstrip("/") + "/chat/completions"
        self._headers = {"Authorization": f"Bearer {api_key}"}

    async def _complete(self, system: str, user: str) -> str:
        data = await self._post(self.url, {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}, self._headers)
        return data["choices"][0]["message"]["content"] or ""


class AnthropicAnalyzer(BaseAnalyzer):
    """Claude via Messages API."""
    name, external = "anthropic", True

    def __init__(self, api_key: str, base_url: str = "https://api.anthropic.com", max_tokens: int = 1024, **kw):
        super().__init__(**kw)
        self.url = base_url.rstrip("/") + "/v1/messages"
        self.max_tokens = max_tokens
        self._headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}

    async def _complete(self, system: str, user: str) -> str:
        data = await self._post(self.url, {
            "model": self.model, "max_tokens": self.max_tokens, "system": system,
            "messages": [{"role": "user", "content": user}]}, self._headers)
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


class GeminiAnalyzer(BaseAnalyzer):
    name, external = "gemini", True

    def __init__(self, api_key: str, base_url: str = "https://generativelanguage.googleapis.com/v1beta", **kw):
        super().__init__(**kw)
        self.base = base_url.rstrip("/")
        self._headers = {"x-goog-api-key": api_key}  # di header, bukan di URL (tidak bocor ke log)

    async def _complete(self, system: str, user: str) -> str:
        data = await self._post(f"{self.base}/models/{self.model}:generateContent", {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"responseMimeType": "application/json"}}, self._headers)
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts)


# ----------------------------------------------------------- Chain + fallback
class AnalyzerChain:
    """Coba provider sesuai urutan; jika gagal lanjut ke berikutnya."""

    def __init__(self, analyzers: list[BaseAnalyzer]):
        self.analyzers = analyzers

    @property
    def label(self) -> str:
        return ">".join(f"{a.name}:{a.model}" for a in self.analyzers)

    async def analyze(self, log_uuid: str, doc: dict) -> tuple[dict, str, str]:
        last: Exception | None = None
        for a in self.analyzers:
            try:
                return await a.analyze(log_uuid, doc), a.name, a.model
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last = exc
                log.warning("Provider %s gagal (%s)%s", a.name, describe_error(exc),
                            ", mencoba berikutnya" if a is not self.analyzers[-1] else "")
        raise last  # type: ignore[misc]

    async def aclose(self) -> None:
        await asyncio.gather(*(a.aclose() for a in self.analyzers), return_exceptions=True)


def build_analyzer(env: Mapping[str, str], persona_path: str) -> AnalyzerChain:
    system = Path(persona_path).read_text(encoding="utf-8")
    mask = env.get("LLM_MASK_SENSITIVE", "true").lower() == "true"
    local_t = float(env.get("OLLAMA_TIMEOUT_S", "600"))
    cloud_t = float(env.get("LLM_CLOUD_TIMEOUT_S", "90"))
    names = [n.strip().lower() for n in env.get("LLM_PROVIDERS", "ollama").split(",") if n.strip()]
    if not names:
        raise ValueError("LLM_PROVIDERS kosong")

    def key(var: str) -> str:
        v = env.get(var, "")
        if not v:
            raise ValueError(f"{var} wajib diisi karena provider terkait diaktifkan")
        return v

    out: list[BaseAnalyzer] = []
    for n in names:
        if n == "ollama":
            out.append(OllamaAnalyzer(env.get("OLLAMA_URL", "http://localhost:11434"),
                                      model=env.get("OLLAMA_MODEL", "llama3.1:8b"),
                                      system_prompt=system, timeout_s=local_t, mask=mask))
        elif n == "openai":
            out.append(OpenAIAnalyzer(key("OPENAI_API_KEY"),
                                      env.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                                      model=env.get("OPENAI_MODEL", "gpt-4o-mini"),
                                      system_prompt=system, timeout_s=cloud_t, mask=mask))
        elif n in ("anthropic", "claude"):
            out.append(AnthropicAnalyzer(key("ANTHROPIC_API_KEY"),
                                         model=env.get("ANTHROPIC_MODEL", "claude-haiku-5-5"),
                                         system_prompt=system, timeout_s=cloud_t, mask=mask))
        elif n in ("gemini", "google"):
            out.append(GeminiAnalyzer(key("GEMINI_API_KEY"),
                                      model=env.get("GEMINI_MODEL", "gemini-2.0-flash"),
                                      system_prompt=system, timeout_s=cloud_t, mask=mask))
        else:
            raise ValueError(f"Provider tidak dikenal: {n}")
    return AnalyzerChain(out)