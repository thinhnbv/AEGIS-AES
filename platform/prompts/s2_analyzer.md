# S2 analyzer prompt (LLM hook). Used when AEGIS_LLM_API_KEY is set.
# Inputs: sanitized RTL text + S1 evidence.json summary.
# Output: YAML with suspicious_regions, predicted_trigger, predicted_payload,
# threatened_asset, confidence.
