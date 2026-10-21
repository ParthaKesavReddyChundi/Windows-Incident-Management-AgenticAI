"""
agents/llm_factory.py
=====================
Factory and invocation utilities for local Ollama LLMs with robust structured output
extraction and schema validation fallbacks.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional, Type, TypeVar

from langchain_ollama import ChatOllama
from pydantic import BaseModel

from config.settings import settings

logger = logging.getLogger("agents.llm")

T = TypeVar("T", bound=BaseModel)


def get_chat_llm(
    model: Optional[str] = None,
    temperature: float = 0.1,
    timeout: float = 60.0,
) -> ChatOllama:
    """Instantiate a ChatOllama instance pointing to local Ollama server."""
    model_name = model or settings.ollama_model
    return ChatOllama(
        model=model_name,
        base_url=settings.ollama_base_url,
        temperature=temperature,
        timeout=timeout,
    )


async def invoke_structured_llm(
    llm: ChatOllama,
    prompt: str,
    schema: Type[T],
    system_instruction: Optional[str] = None,
) -> T:
    """
    Invoke LLM requesting structured Pydantic output, with regex/JSON extraction fallback.
    """
    # 1. First attempt: LangChain native with_structured_output
    try:
        structured_llm = llm.with_structured_output(schema)
        messages = []
        if system_instruction:
            messages.append(("system", system_instruction))
        messages.append(("user", prompt))

        result = await structured_llm.ainvoke(messages)
        if isinstance(result, schema):
            return result
        elif isinstance(result, dict):
            return schema.model_validate(result)
    except Exception as e:
        logger.warning(
            f"Native structured output attempt failed ({e}); attempting text JSON parsing fallback"
        )

    # 2. Second attempt: Raw invocation with JSON instruction
    json_prompt = (
        f"{prompt}\n\n"
        f"IMPORTANT: Respond ONLY with a valid JSON object matching this schema:\n"
        f"{json.dumps(schema.model_json_schema(), indent=2)}\n"
        f"Do NOT include markdown formatting or commentary outside the JSON."
    )
    messages = []
    if system_instruction:
        messages.append(("system", system_instruction))
    messages.append(("user", json_prompt))

    raw_response = await llm.ainvoke(messages)
    text = str(raw_response.content).strip()

    # Extract JSON substring
    try:
        # Match ```json ... ``` or first { ... }
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            json_str = match.group(1)
        else:
            match_brace = re.search(r"(\{.*\})", text, re.DOTALL)
            json_str = match_brace.group(1) if match_brace else text

        # Attempt to decode JSON, with backslash sanitization for Windows paths
        try:
            data = json.loads(json_str, strict=False)
        except json.JSONDecodeError:
            # Fix unescaped backslashes commonly emitted in Windows paths/event logs
            sanitized = re.sub(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', json_str)
            data = json.loads(sanitized, strict=False)


        if isinstance(data, dict):
            if "properties" in data and isinstance(data["properties"], dict):
                props = data["properties"]
                if any(k in props for k in schema.model_fields.keys()):
                    data = props
            elif "response" in data and isinstance(data["response"], dict):
                resp = data["response"]
                if any(k in resp for k in schema.model_fields.keys()):
                    data = resp

        return schema.model_validate(data)

    except Exception as parse_err:
        logger.error(
            f"Failed to parse structured JSON from LLM output: {parse_err}. Raw text:\n{text}"
        )
        raise ValueError(
            f"Could not extract valid {schema.__name__} from LLM response: {parse_err}"
        )
