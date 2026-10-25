"""Provider-agnostic LLM client with file-hash caching and usage logging.

Supported providers (pick with LLM_PROVIDER, default: first one with a key set):
  groq        free plan, OpenAI-compatible API, key GROQ_API_KEY
  gemini      free tier (Flash / Flash-Lite), key GEMINI_API_KEY
  openrouter  ':free' models, key OPENROUTER_API_KEY
  ollama      local, no key, no cost (needs `ollama pull <vision model>`)

LLM_MODEL overrides the default model for the chosen provider. Free-tier model
IDs change often; check the provider's model list if a call returns 404.

Every call (and every cache hit) is appended to evaluation/usage_log.jsonl so
evaluation/usage_report.md can be generated from the final run. API keys are
read from the environment and never written anywhere.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import mimetypes
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / ".cache" / "llm"
USAGE_LOG = ROOT / "evaluation" / "usage_log.jsonl"

PROVIDERS = {
    "groq": {
        "kind": "openai", "url": "https://api.groq.com/openai/v1/chat/completions",
        "key_env": "GROQ_API_KEY", "model": "qwen/qwen3.8-27b",
        "max_images": 5, "free": True,
    },
    "openrouter": {
        "kind": "openai", "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_API_KEY", "model": "qwen/qwen2.5-vl-72b-instruct:free",
        "max_images": 5, "free": True,
    },
    "ollama": {
        "kind": "openai",
        "url": os.environ.get("OLLAMA_URL", "http://localhost:11434") + "/v1/chat/completions",
        "key_env": "", "model": "qwen2.5vl:7b", "max_images": 5, "free": True,
    },
    "gemini": {
        "kind": "gemini",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "key_env": "GEMINI_API_KEY", "model": "gemini-3.5-flash-lite",
        "max_images": 16, "free": True,
    },
}


def provider_name() -> str:
    p = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if p:
        if p not in PROVIDERS:
            raise ValueError(f"LLM_PROVIDER must be one of {sorted(PROVIDERS)}")
        return p
    for name in ("groq", "gemini", "openrouter"):
        if os.environ.get(PROVIDERS[name]["key_env"]):
            return name
    return "ollama" if os.environ.get("USE_OLLAMA") else ""


def model_name(provider: str) -> str:
    return os.environ.get("LLM_MODEL") or PROVIDERS[provider]["model"]


def available() -> bool:
    p = provider_name()
    if not p:
        return False
    if p == "ollama":
        try:
            urllib.request.urlopen(PROVIDERS["ollama"]["url"].replace("/v1/chat/completions", "/api/tags"), timeout=3)
            return True
        except Exception:
            return False
    return bool(os.environ.get(PROVIDERS[p]["key_env"]))


def file_sha(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _log_usage(entry: dict) -> None:
    USAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(USAGE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# --------------------------------------------------------------------------- files -> images
def _images_for(path: Path, max_images: int) -> list[tuple[str, bytes]]:
    """Return [(mime, bytes)]. PDFs are rendered to PNG pages for image-only APIs."""
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    if mime != "application/pdf":
        return [(mime, path.read_bytes())]
    import pypdfium2 as pdfium  # type: ignore

    pdf = pdfium.PdfDocument(str(path))
    out = []
    for i in range(min(len(pdf), max_images)):
        img = pdf[i].render(scale=2).to_pil()
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        out.append(("image/png", buf.getvalue()))
    return out


def _b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode()


# --------------------------------------------------------------------------- HTTP
def _post_json(url: str, payload: dict, headers: dict, retries: int = 6) -> dict:
    body = json.dumps(payload).encode()
    delay = 5.0
    for attempt in range(retries):
        req = urllib.request.Request(url, data=body, headers={"content-type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            if e.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                wait = float(e.headers.get("retry-after") or delay)
                time.sleep(min(wait, 120))
                delay *= 2
                continue
            raise RuntimeError(f"HTTP {e.code} from {url.split('?')[0]}: {detail}") from None
    raise RuntimeError("unreachable")


def _call_openai(cfg: dict, model: str, system: str, text: str, files: list[Path], max_tokens: int):
    content = []
    for f in files:
        for mime, data in _images_for(f, cfg["max_images"]):
            content.append({"type": "image_url", "image_url": {"url": f"data:{mime};base64,{_b64(data)}"}})
    content.append({"type": "text", "text": text})
    payload = {
        "model": model, "max_tokens": max_tokens, "temperature": 0,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}],
    }
    headers = {}
    if cfg["key_env"]:
        headers["authorization"] = f"Bearer {os.environ[cfg['key_env']]}"
    resp = _post_json(cfg["url"], payload, headers)
    msg = resp["choices"][0]["message"]
    out = msg.get("content") or ""
    if isinstance(out, list):
        out = "".join(p.get("text", "") for p in out)
    u = resp.get("usage") or {}
    return out, resp.get("model", model), u.get("prompt_tokens", 0), u.get("completion_tokens", 0)


def _call_gemini(cfg: dict, model: str, system: str, text: str, files: list[Path], max_tokens: int):
    parts = []
    for f in files:
        mime = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        parts.append({"inline_data": {"mime_type": mime, "data": _b64(f.read_bytes())}})
    parts.append({"text": text})
    payload = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": max_tokens,
                             "responseMimeType": "application/json"},
    }
    headers = {"x-goog-api-key": os.environ[cfg["key_env"]]}
    resp = _post_json(cfg["url"].format(model=model), payload, headers)
    cands = resp.get("candidates") or [{}]
    out = "".join(p.get("text", "") for p in (cands[0].get("content") or {}).get("parts", []))
    u = resp.get("usageMetadata") or {}
    return out, model, u.get("promptTokenCount", 0), u.get("candidatesTokenCount", 0)


# --------------------------------------------------------------------------- public API
def call(*, purpose: str, ref: str, system: str, text: str, files: list[str | Path] = (),
         cache_key: str, max_tokens: int = 4000, run_id: str = "") -> str:
    """Return model text. Cached on disk by cache_key + provider + model."""
    provider = provider_name()
    if not provider:
        raise RuntimeError("no LLM provider configured (set GROQ_API_KEY, GEMINI_API_KEY, "
                           "OPENROUTER_API_KEY, or USE_OLLAMA=1)")
    cfg = PROVIDERS[provider]
    model = model_name(provider)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe_model = model.replace("/", "_").replace(":", "_")
    cpath = CACHE_DIR / f"{cache_key}__{provider}__{safe_model}.json"
    base = {"ts": _now(), "run_id": run_id, "purpose": purpose, "ref": ref,
            "provider": provider, "model": model, "free_tier": cfg["free"]}
    if cpath.exists():
        cached = json.loads(cpath.read_text(encoding="utf-8"))
        _log_usage({**base, "cache_hit": True, "input_tokens": 0, "output_tokens": 0,
                    "original_input_tokens": cached.get("input_tokens", 0),
                    "original_output_tokens": cached.get("output_tokens", 0)})
        return cached["text"]

    paths = [Path(f) for f in files]
    fn = _call_gemini if cfg["kind"] == "gemini" else _call_openai
    t0 = time.time()
    out, used_model, tin, tout = fn(cfg, model, system, text, paths, max_tokens)
    rec = {"text": out, "model": used_model, "input_tokens": tin, "output_tokens": tout}
    cpath.write_text(json.dumps(rec), encoding="utf-8")
    _log_usage({**base, "model": used_model, "cache_hit": False, "input_tokens": tin,
                "output_tokens": tout, "latency_s": round(time.time() - t0, 2)})
    return out


def read_cached(cache_key: str, *, purpose: str = "", ref: str = "", run_id: str = "") -> str | None:
    """Cached answer from any provider/model (lets a run without keys reuse earlier calls)."""
    if not CACHE_DIR.exists():
        return None
    for cpath in sorted(CACHE_DIR.glob(f"{cache_key}__*.json")):
        rec = json.loads(cpath.read_text(encoding="utf-8"))
        provider = cpath.stem.split("__")[1]
        _log_usage({"ts": _now(), "run_id": run_id, "purpose": purpose, "ref": ref,
                    "provider": provider, "model": rec.get("model", ""),
                    "free_tier": PROVIDERS.get(provider, {}).get("free", True), "cache_hit": True,
                    "input_tokens": 0, "output_tokens": 0,
                    "original_input_tokens": rec.get("input_tokens", 0),
                    "original_output_tokens": rec.get("output_tokens", 0)})
        return rec["text"]
    return None


def parse_json(text: str):
    """Extract the first JSON object/array from model text."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1].rsplit("```", 1)[0]
    starts = [i for i in (t.find("{"), t.find("[")) if i >= 0]
    if not starts:
        raise ValueError("no JSON in model output")
    return json.JSONDecoder().raw_decode(t[min(starts):])[0]
