from __future__ import annotations

import abc
import os
import sys
from dataclasses import dataclass
from typing import Optional

import requests

from src.config import (
    LLM_BACKEND_DEFAULT,
    GROQ_MODEL_DEFAULT,
    OLLAMA_MODEL_DEFAULT,
    OLLAMA_URL_DEFAULT,
)

class LLMBackend(abc.ABC):
    @abc.abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_model_name(self) -> str:
        raise NotImplementedError


@dataclass
class OllamaBackend(LLMBackend):
    model: str = OLLAMA_MODEL_DEFAULT
    base_url: str = OLLAMA_URL_DEFAULT

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            resp = requests.post(
                f"{self.base_url.rstrip('/')}/api/generate",
                json=payload,
                timeout=90,
            )
        except requests.RequestException as exc:
            raise RuntimeError("Ollama is not running") from exc

        if resp.status_code != 200:
            raise RuntimeError(f"Ollama request failed with status {resp.status_code}")

        data = resp.json()
        out = data.get("response")
        if not isinstance(out, str):
            raise RuntimeError("Ollama response is missing text")
        return out

    def get_model_name(self) -> str:
        return self.model


@dataclass
class GroqBackend(LLMBackend):
    model: str = GROQ_MODEL_DEFAULT
    api_key: str = ""

    def __post_init__(self) -> None:
        api_key = str(self.api_key or "").strip() or str(os.getenv("GROQ_API_KEY", "")).strip()
        if not api_key:
            raise RuntimeError("Please set GROQ_API_KEY")
        try:
            from groq import Groq  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("Groq SDK is not installed") from exc
        self._client = Groq(api_key=api_key)

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        chat = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.2,
        )
        content = chat.choices[0].message.content
        if not isinstance(content, str):
            raise RuntimeError("Groq response is missing text")
        return content

    def get_model_name(self) -> str:
        return self.model


@dataclass
class LocalMockBackend(LLMBackend):
    model: str = "local_mock"

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        _ = system_prompt
        _ = prompt
        return (
            '{"verdict":"WARN","issues":[{"check_name":"llm_disabled","severity":"WARN",'
            '"message":"LLM disabled (local_mock)","hypotheses":["unknown"],'
            '"verification_steps":["SELECT run_id FROM step1.step1_run_registry LIMIT 1;",'
            '"psql -d $CLIENT_DB_NAME -c \\"SELECT COUNT(*) FROM step1.step1_orders;\\""]}],'
            '"recommendations":["Start Ollama for richer analysis or explicitly allow remote backend."]}'
        )

    def get_model_name(self) -> str:
        return self.model


def _warn(msg: str) -> None:
    print(msg, file=sys.stderr)


def _info(msg: str) -> None:
    print(msg, file=sys.stderr)


def _is_remote_backend(backend_name: str) -> bool:
    return backend_name not in {"ollama", "none", "local_mock"}


def _ollama_available(base_url: str) -> bool:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=2)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def _resolve_backend_name(backend_name: Optional[str]) -> str:
    selected = (backend_name or os.getenv("LLM_BACKEND") or LLM_BACKEND_DEFAULT).strip().lower()
    if selected not in {"groq", "ollama", "auto", "none", "local_mock"}:
        raise RuntimeError("Unsupported backend. Use 'groq', 'ollama', 'auto', or 'local_mock'.")
    if selected != "auto":
        return selected

    ollama_url = os.getenv("OLLAMA_URL", OLLAMA_URL_DEFAULT)
    allow_remote = os.getenv("LLM_ALLOW_REMOTE", "0") == "1"
    has_groq_key = bool(os.getenv("GROQ_API_KEY"))
    if not allow_remote:
        if _ollama_available(ollama_url):
            return "ollama"
        if os.getenv("LLM_ENABLE_LOCAL_MOCK", "1") == "1":
            _warn("WARN: Ollama unavailable; auto mode using local mock backend.")
            return "local_mock"
        raise RuntimeError("No local LLM backend available")

    if has_groq_key:
        return "groq"
    if _ollama_available(ollama_url):
        _warn("WARN: Groq unavailable for auto mode; falling back to Ollama.")
        return "ollama"
    if os.getenv("LLM_ENABLE_LOCAL_MOCK", "1") == "1":
        _warn("WARN: No Groq/Ollama available; auto mode using local mock backend.")
        return "local_mock"
    raise RuntimeError("No local LLM backend available")


def get_llm_backend(
    backend_name: Optional[str] = None,
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
) -> LLMBackend:
    selected = _resolve_backend_name(backend_name)

    if _is_remote_backend(selected) and os.getenv("LLM_ALLOW_REMOTE", "0") != "1":
        raise RuntimeError("Remote LLM is blocked. Set LLM_ALLOW_REMOTE=1 to allow.")

    if selected == "groq":
        backend = GroqBackend(
            model=(model_name or os.getenv("GROQ_MODEL", GROQ_MODEL_DEFAULT)),
            api_key=str(api_key or "").strip(),
        )
    elif selected in {"none", "local_mock"}:
        backend = LocalMockBackend()
    else:
        ollama_url = os.getenv("OLLAMA_URL", OLLAMA_URL_DEFAULT)
        if not _ollama_available(ollama_url):
            raise RuntimeError("No local LLM backend available")
        backend = OllamaBackend(
            model=(model_name or os.getenv("OLLAMA_MODEL", OLLAMA_MODEL_DEFAULT)),
            base_url=ollama_url,
        )

    llm_mode = "remote_allowed" if os.getenv("LLM_ALLOW_REMOTE", "0") == "1" else "local_only"
    _info(f"INFO: LLM_MODE={llm_mode} backend={selected} model={backend.get_model_name()}")
    return backend


def _dev_self_check() -> int:
    try:
        backend = get_llm_backend("auto")
        print(f"SELF_CHECK auto_backend={backend.get_model_name()}")
        return 0
    except Exception:
        print("SELF_CHECK error=backend_unavailable")
        return 1


if __name__ == "__main__":
    if os.getenv("LLM_SELF_CHECK", "0") == "1":
        raise SystemExit(_dev_self_check())
