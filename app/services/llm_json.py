"""Shared helpers for parsing JSON out of K2-Think-v2 responses.

K2-Think-v2 is a reasoning model: it often "thinks out loud" (sometimes inside
<think>...</think> tags) and emits the actionable JSON at the very end, possibly
wrapped in markdown fences. These helpers extract a JSON object from such
free-form replies. Used by the K2 agent for parsing tool-call decisions.
"""
from __future__ import annotations

import json
import re


def is_api_error(response: str) -> bool:
    """True if the LLM client returned an infrastructure error string."""
    return isinstance(response, str) and response.startswith("Error: ")


def extract_think_block(response: str) -> str:
    """
    Return the raw reasoning text K2-Think-v2 emitted inside <think>...</think>.

    This is the inverse of ``strip_reasoning``: instead of discarding the
    chain-of-thought, we capture it so it can be rendered as a structured
    thought timeline. Handles multiple think blocks (joined in order) and a
    dangling/unbalanced opening tag (returns everything after the last
    ``<think>``). Returns "" when no reasoning block is present.
    """
    if not isinstance(response, str) or not response:
        return ""
    blocks = re.findall(
        r"<think>(.*?)</think>", response, flags=re.DOTALL | re.IGNORECASE
    )
    if blocks:
        return "\n\n".join(b.strip() for b in blocks if b.strip()).strip()
    # Unbalanced opening tag: keep everything after the last <think>.
    lower = response.lower()
    if "<think>" in lower:
        idx = lower.rfind("<think>")
        tail = response[idx + len("<think>"):]
        # Drop a trailing closing tag if one slipped through.
        return re.sub(r"</think>", " ", tail, flags=re.IGNORECASE).strip()
    return ""


def strip_reasoning(response: str) -> str:
    """Remove <think>...</think> reasoning blocks so only the answer remains."""
    text = response.strip()
    # Drop fully-formed reasoning blocks.
    text = re.sub(r"<think>.*?</think>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    # If a closing tag remains (unbalanced), keep only what follows the last one.
    lower = text.lower()
    if "</think>" in lower:
        idx = lower.rfind("</think>")
        text = text[idx + len("</think>"):]
    # Drop any dangling opening tag.
    text = re.sub(r"<think>", " ", text, flags=re.IGNORECASE)
    return text.strip()


def iter_brace_objects(text: str):
    """Yield top-level {...} substrings, ignoring braces inside JSON strings."""
    depth = 0
    start = None
    in_str = False
    escape = False
    quote = ""
    for i, ch in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    yield text[start:i + 1]
                    start = None


def extract_json_object(response: str, required_key: str | None = None) -> dict | None:
    """
    Extract a JSON object from a (possibly reasoning-wrapped) LLM response.

    Strips <think> blocks, then looks for a JSON object in markdown fences, via a
    balanced-brace scan (preferring the LAST match, since reasoning models emit
    the final answer after the prose), and finally tries the whole text.

    If ``required_key`` is given, only objects containing that key are accepted.
    Returns the parsed dict, or None if nothing parseable was found.
    """
    text = strip_reasoning(response)

    def _load(candidate: str) -> dict | None:
        candidate = candidate.strip()
        if not candidate:
            return None
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(obj, dict):
            return None
        if required_key is not None and required_key not in obj:
            return None
        return obj

    # 1) Markdown-fenced blocks (```json ... ``` or ``` ... ```).
    for block in re.findall(
        r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE
    ):
        obj = _load(block)
        if obj is not None:
            return obj

    # 2) Balanced-brace scan; prefer the last valid object.
    valid = [obj for obj in (_load(c) for c in iter_brace_objects(text)) if obj is not None]
    if valid:
        return valid[-1]

    # 3) Whole response as a single JSON document.
    return _load(text)



def iter_bracket_arrays(text: str):
    """Yield top-level [...] substrings, ignoring brackets inside JSON strings."""
    depth = 0
    start = None
    in_str = False
    escape = False
    quote = ""
    for i, ch in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
        elif ch == "[":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "]":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    yield text[start:i + 1]
                    start = None


def extract_json_array(response: str) -> list | None:
    """
    Extract a JSON array from a (possibly reasoning-wrapped) LLM response.

    Mirrors ``extract_json_object`` but targets a top-level JSON list, which is
    the shape K2-Think-v2 returns when asked to format its reasoning into a
    structured thought timeline. Strips <think> blocks, then checks markdown
    fences, a balanced-bracket scan (preferring the LAST match), and finally the
    whole text. Returns the parsed list, or None when nothing parseable is found.
    """
    text = strip_reasoning(response)

    def _load(candidate: str) -> list | None:
        candidate = candidate.strip()
        if not candidate:
            return None
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return None
        return obj if isinstance(obj, list) else None

    # 1) Markdown-fenced blocks (```json ... ``` or ``` ... ```).
    for block in re.findall(
        r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE
    ):
        arr = _load(block)
        if arr is not None:
            return arr

    # 2) Balanced-bracket scan; prefer the last valid array.
    valid = [a for a in (_load(c) for c in iter_bracket_arrays(text)) if a is not None]
    if valid:
        return valid[-1]

    # 3) Whole response as a single JSON document.
    return _load(text)
