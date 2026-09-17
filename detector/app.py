"""Prompt injection-klassificerare exponerad som en liten HTTP-tjänst.

LiteLLM-guardrailen anropar /classify. Att köra modellen i en egen container
håller LiteLLM-imagen orörd och gör det enkelt att byta klassificerare.
"""

import os

from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline

MODEL_ID = os.environ.get("DETECTOR_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
MODEL_REVISION = os.environ.get("DETECTOR_MODEL_REVISION", "90c9989b1a342275dd0d1a95aad283c04e075671")

# Modellen tar max 512 tokens. Längre texter (t.ex. dokument) delas upp i
# överlappande bitar så att en instruktion i slutet av ett dokument inte klipps bort.
CHUNK_CHARS = 1500
CHUNK_OVERLAP = 200

app = FastAPI()
classifier = pipeline(
    "text-classification",
    model=MODEL_ID,
    revision=MODEL_REVISION,
    truncation=True,
    max_length=512,
)


class ClassifyRequest(BaseModel):
    text: str


def split_into_chunks(text: str) -> list[str]:
    if len(text) <= CHUNK_CHARS:
        return [text]
    step = CHUNK_CHARS - CHUNK_OVERLAP
    return [text[i : i + CHUNK_CHARS] for i in range(0, len(text) - CHUNK_OVERLAP, step)]


def injection_score(result: dict) -> float:
    # Modellen returnerar etiketten INJECTION eller SAFE med sannolikhet.
    return result["score"] if result["label"] == "INJECTION" else 1.0 - result["score"]


@app.post("/classify")
def classify(request: ClassifyRequest) -> dict:
    chunks = split_into_chunks(request.text)
    scores = [injection_score(r) for r in classifier(chunks)]
    return {"score": max(scores), "chunks": len(chunks), "model": MODEL_ID}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL_ID}
