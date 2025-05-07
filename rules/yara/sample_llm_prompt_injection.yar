rule LLM_Prompt_Injection
{
    meta:
        description = "Detects prompt injection attempts targeting LLMs"
        threat = "manipulation"
        severity = "high"
    strings:
        $injection1 = "ignore previous instructions"
        $injection2 = "disregard all prior input"
    condition:
        any of them
}