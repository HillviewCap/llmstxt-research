rule LLM_Evasion_Technique
{
    meta:
        description = "Detects evasion techniques used to bypass LLM content filters"
        threat = "evasion"
        severity = "medium"
    strings:
        $evasion1 = "bypass content filter"
        $evasion2 = "circumvent safety system"
    condition:
        any of them
}