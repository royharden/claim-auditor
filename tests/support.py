"""Small explicit inputs, not measured report fixtures or an alternative policy."""

from pathlib import Path

from claim_auditor.contracts import (
    Claim, EvaluationPacket, Finding, GoldAtom, Inventory, Predicate, PredictionRow,
    Span, canonical_json, sha256,
)
from claim_auditor.inventory.raw import RawDocument
from claim_auditor.snapshot import create_fixture_snapshot


def frozen_source(base: Path, *, readme: bytes = b"The function `work` is declared.\n",
                  code: bytes = b"def work():\n    pass\n", extra=None):
    source = base / "source"
    source.mkdir()
    for name, raw in {"README.md": readme, "tiny.py": code, **(extra or {})}.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    root = base / "snapshot"
    return create_fixture_snapshot(source, root), root


def span_for(snapshot, raw: bytes, *, path="README.md", start=0, end=None):
    end = len(raw) if end is None else end
    first, last = RawDocument.decode(raw).line_bounds(start, end)
    quote = raw[start:end].decode("utf-8")
    return Span(snapshot_id=snapshot.snapshot_id, file_sha256=sha256(raw), path=path,
                start_byte=start, end_byte=end, start_line=first, end_line=last,
                quote=quote, quote_sha256=sha256(raw[start:end]))


def predicate(**changes):
    fields = dict(predicate_id="p:work", kind="symbol_declared", subject="work",
                  module="tiny", path=None, key=None, expected=None, negated=False,
                  condition=None, qualifiers=[], pattern=None)
    fields.update(changes)
    return Predicate(**fields)


def claim(span, query=None, *, identifier="claim:work"):
    query = predicate() if query is None else query
    return Claim(claim_id=identifier, parent_id="sentence:work", atom_ordinal=0,
                 kind=query.kind, normalized=span.quote, span=span, predicates=[query],
                 extraction_method="rules", extraction_version="regression-input/1",
                 uncertainty=[])


def finding(atom, verdict, *, identifier=None):
    # Explicit synthetic scorer inputs; citation correctness is tested separately.
    ids = [p.predicate_id for p in atom.predicates]
    return Finding(claim=atom, verdict=verdict,
                   support_relation={"verified": "supports", "missing": "contradicts",
                                     "unknown": "no_evidence"}[verdict],
                   reason="synthetic_scorer_control",
                   supported_predicate_ids=ids if verdict == "verified" else [],
                   unresolved_predicate_ids=[] if verdict == "verified" else ids,
                   accused_predicate_ids=ids if verdict == "missing" else [],
                   evidence_ids=[] if verdict == "unknown" else [identifier or "e:input"],
                   complete=True,
                   citation_validation="not_applicable" if verdict == "unknown" else "valid",
                   model_proposal=None)


def prediction(atom, verdict, *, identifier="prediction:work", status="prediction"):
    result = finding(atom, verdict)
    return PredictionRow(prediction_id=identifier, family_id="dev:control", finding=result,
                         status=status, error=None,
                         accused_predicate_ids=result.accused_predicate_ids)


def gold(atom, verdict, *, identifier="gold:work", answerable=True):
    result = finding(atom, verdict)
    return GoldAtom(gold_id=identifier, family_id="dev:control", claim=atom, verdict=verdict,
                    support_relation=result.support_relation, answerable=answerable,
                    supported_predicate_ids=result.supported_predicate_ids,
                    unresolved_predicate_ids=result.unresolved_predicate_ids,
                    accused_predicate_ids=result.accused_predicate_ids,
                    annotator_type="agent", annotator_id="D6-synthetic-control",
                    rationale="Hand-authored adversarial control, never human gold.",
                    adjudicated_at=None, disagreements=[])


def packet_for(snapshot, readme: bytes, *, excerpts=None):
    fields = dict(schema_version="claim-auditor/1", packet_version="readme-anchors/1",
                  snapshot_id=snapshot.snapshot_id,
                  snapshot_manifest_digest=snapshot.manifest_digest,
                  readme_path="README.md", readme_sha256=sha256(readme),
                  readme_text=readme.decode("utf-8"), excerpts=excerpts or [],
                  scope_entries=snapshot.entries, exclusions=snapshot.exclusions,
                  candidate_count=len(excerpts or []), omitted_count=0,
                  complete=snapshot.complete, absence_certificates=False)
    return EvaluationPacket(**fields, packet_digest=sha256(canonical_json(fields)))


def inventory_for(snapshot, atom):
    return Inventory(snapshot_id=snapshot.snapshot_id, readme_path="README.md",
                     readme_sha256=atom.span.file_sha256, claims=[atom], blocks=[],
                     complete=True, errors=[], extraction_version="regression-input/1")
