# Trojan-identifier neutral map, shared by S0 (sanitize) and S3 (generate).
# Kept in sync so both stages agree on which identifiers are Trojan-related.
NEUTRAL_MAP = {
    "trojan_trig": "sanitize_cond_a",
    "result_maybe_evil": "sanitize_result_b",
}
