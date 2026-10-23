"""Hand-authored protocol examples only; never measured inference or usage.

These are incomplete schema illustrations, not an evaluation packet, benchmark
output, shipped model response, authorized endpoint or real account configuration.
No transport is instantiated here. Values labeled fixture are simulated inputs.
"""

SAMPLE_OPENAI_REQUEST = {
    "model": "fixture-model",
    "stream": False,
    "store": False,
    "n": 1,
    "max_completion_tokens": 64,
    "messages": [{"role": "system", "content": "Fixture-only JSON shape illustration."},
                 {"role": "user", "content": "{}"}],
}

SAMPLE_OPENAI_RESPONSE = {
    "id": "fixture-openai-001",
    "model": "fixture-model",
    "choices": [{"finish_reason": "stop", "message": {"role": "assistant",
                                                         "content": '{"atoms":[]}', "refusal": None}}],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}

SAMPLE_ANTHROPIC_REQUEST = {
    "model": "fixture-model",
    "stream": False,
    "max_tokens": 64,
    "system": "Fixture-only JSON shape illustration.",
    "messages": [{"role": "user", "content": "{}"}],
}

SAMPLE_ANTHROPIC_RESPONSE = {
    "id": "fixture-anthropic-001",
    "model": "fixture-model",
    "type": "message",
    "role": "assistant",
    "content": [{"type": "text", "text": '{"atoms":[]}'}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 1, "output_tokens": 1,
              "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
}
