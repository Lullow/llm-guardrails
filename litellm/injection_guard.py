"""Egna guardrails för LiteLLM-proxyn.

InjectionClassifierGuard (pre_call): skickar användar- och verktygsinnehåll till
klassificeringstjänsten och stoppar anropet om sannolikheten för injection är hög.

OutputLeakGuard (post_call): stoppar svar som läcker canary-token/hemlig kod
eller innehåller länkar till domäner utanför en tillåtelselista.
"""

import os
import re
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException

from litellm._logging import verbose_proxy_logger
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.guardrails import GuardrailEventHooks

# Systemprompten skrivs av oss själva och räknas som betrodd. Att klassificera den
# ger bara falsklarm, eftersom den innehåller regler som liknar instruktioner.
UNTRUSTED_ROLES = {"user", "tool", "function"}
URL_PATTERN = re.compile(r"https?://[^\s)\"'>\]]+", re.IGNORECASE)


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part.get("text", "") for part in content if isinstance(part, dict))
    return ""


def _block(guardrail_name: str, reason: str, **details) -> HTTPException:
    return HTTPException(status_code=400, detail={"error": f"[{guardrail_name}] {reason}", **details})


class InjectionClassifierGuard(CustomGuardrail):
    def __init__(self, **kwargs):
        self.detector_url = os.environ["DETECTOR_URL"]
        self.threshold = float(os.environ.get("INJECTION_THRESHOLD", "0.5"))
        super().__init__(**kwargs)

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type,
    ):
        if not self.should_run_guardrail(data=data, event_type=GuardrailEventHooks.pre_call):
            return data

        async with httpx.AsyncClient(timeout=30) as client:
            for index, message in enumerate(data.get("messages") or []):
                if message.get("role") not in UNTRUSTED_ROLES:
                    continue
                text = _text_of(message.get("content"))
                if not text.strip():
                    continue
                response = await client.post(self.detector_url, json={"text": text})
                # Fail closed: om detektorn inte svarar släpps inget igenom.
                response.raise_for_status()
                score = response.json()["score"]
                verbose_proxy_logger.debug("%s: message %d score=%.3f", self.guardrail_name, index, score)
                if score >= self.threshold:
                    raise _block(
                        self.guardrail_name,
                        "Possible prompt injection detected.",
                        score=round(score, 3),
                        message_index=index,
                    )
        return data


class OutputLeakGuard(CustomGuardrail):
    def __init__(self, **kwargs):
        self.secrets = [s for s in (os.environ.get("CANARY_TOKEN"), os.environ.get("SECRET_CODE")) if s]
        self.allowed_domains = {
            d.strip().lower() for d in os.environ.get("ALLOWED_LINK_DOMAINS", "").split(",") if d.strip()
        }
        super().__init__(**kwargs)

    def _domain_allowed(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response,
    ):
        if not self.should_run_guardrail(data=data, event_type=GuardrailEventHooks.post_call):
            return response

        for choice in getattr(response, "choices", []):
            # Resonerande modeller (t.ex. qwen3) returnerar tankekedjan i reasoning_content,
            # som också når klienten. En läcka där är lika allvarlig som i själva svaret.
            text = "\n".join(
                _text_of(getattr(choice.message, field, None)) for field in ("content", "reasoning_content")
            )
            for secret in self.secrets:
                if secret.lower() in text.lower():
                    raise _block(self.guardrail_name, "Response contains confidential data.")
            for url in URL_PATTERN.findall(text):
                if not self._domain_allowed(url):
                    raise _block(
                        self.guardrail_name,
                        "Response links to a domain outside the allow-list.",
                        domain=urlparse(url).hostname,
                    )
        return response
