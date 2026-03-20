from __future__ import annotations

# Which backend to use by default
LLM_BACKEND_DEFAULT = "auto"

# Groq default model (fast + cheap)
GROQ_MODEL_DEFAULT = "llama-3.1-8b-instant"

# Commander Priority preferred model on Groq (Agent #3 reasoning / PM)
COMMANDER_MODEL_DEFAULT = "qwen/qwen3-32b"

# Ollama fallback model (local lightweight)
OLLAMA_MODEL_DEFAULT = "gemma3:1b"

# Ollama server URL
OLLAMA_URL_DEFAULT = "http://localhost:11434"
