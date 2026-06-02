"""Tests for RemediationService.clean_patch (stripping K2 reasoning)."""
from app.services.remediation import RemediationService


def test_clean_patch_strips_think_block():
    """A <think> monologue is removed, leaving only the fenced code."""
    raw = (
        "<think>We need to respond with only the fixed code. The vulnerability "
        "is SQL injection, so use parameterized queries...</think>\n"
        "```python\n"
        "query = 'SELECT * FROM users WHERE id = %s'\n"
        "cur.execute(query, (uid,))\n"
        "```"
    )
    cleaned = RemediationService.clean_patch(raw)
    assert "We need to respond" not in cleaned
    assert "<think>" not in cleaned
    assert "cur.execute(query, (uid,))" in cleaned


def test_clean_patch_prefers_last_code_block():
    """When reasoning shows an example block, the final answer block wins."""
    raw = (
        "<think>Maybe something like:\n```python\nbad = eval(x)\n```\n"
        "no, that's wrong.</think>\n"
        "```python\nsafe = int(x)\n```"
    )
    cleaned = RemediationService.clean_patch(raw)
    assert "safe = int(x)" in cleaned
    assert "bad = eval(x)" not in cleaned


def test_clean_patch_handles_unterminated_think():
    """A truncated/unbalanced </think> still yields the trailing answer."""
    raw = "long reasoning here </think> def fixed(): return True"
    cleaned = RemediationService.clean_patch(raw)
    assert cleaned == "def fixed(): return True"
    assert "long reasoning" not in cleaned


def test_clean_patch_no_fence_returns_dethought_text():
    """With no code fence, return the de-thought text as-is."""
    raw = "<think>reasoning</think>def f(): pass"
    cleaned = RemediationService.clean_patch(raw)
    assert cleaned == "def f(): pass"


def test_clean_patch_empty():
    assert RemediationService.clean_patch("") == ""
