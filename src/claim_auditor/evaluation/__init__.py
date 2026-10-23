"""Source-only preparation and explicitly descriptive scoring ports."""

from claim_auditor.evaluation.packet import PACKET_VERSION, code_digest, prepare_dev_packet, prepare_evaluation
from claim_auditor.evaluation.scoring import MATCHER_VERSION, score_predictions, score_rows
from claim_auditor.evaluation.baseline import BASELINE_VERSION, run_packet_grep
from claim_auditor.evaluation.measurements import family_bootstrap, summarize_attempts
from claim_auditor.evaluation.runner import RUNNER_VERSION, run_paired
from claim_auditor.evaluation.verify import score_paired, verify_paired
from claim_auditor.evaluation.live_runner import run_live_experiment

__all__ = ["BASELINE_VERSION", "MATCHER_VERSION", "PACKET_VERSION", "RUNNER_VERSION", "code_digest", "family_bootstrap", "prepare_dev_packet", "prepare_evaluation", "run_live_experiment", "run_packet_grep", "run_paired", "score_paired", "score_predictions", "score_rows", "summarize_attempts", "verify_paired"]
