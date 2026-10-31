import csv
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from PIL import Image as PILImage
from typesafe_sdk import Choice, Image, Noul, Score, SystemOneResponse

from jev_client import JevClient, convert_images
from main import (compare_results, evaluate_test, export_results, flatten,
                  load_tests, result_row, summarize)


def case(variant="clean", expected="block"):
    return {"id": "a", "variant": variant, "state": {"text": "untrusted"},
            "questions": {
                "decision": {"type": "choice", "instructions": "Evaluate policy", "criteria": {
                    "allow": "Permitted", "block": "Prohibited", "flag": "Review"}},
                "risk": {"type": "score", "criteria": ["low", "high"]},
                "violation": {"type": "noul", "instructions": "Policy violated?"}},
            "expected": {"decision": expected},
            "metadata": {"guardrail_questions": ["decision"], "trusted_fields": ["security_policy"]}}


def response(choice="block", p=.1):
    return {"model": "jev-test", "usage": {"input_tokens": 10, "output_tokens": 5}, "answers": {
        "decision": {"type": "choice", "choice": choice, "confidence": .9,
                     "probabilities": {"allow": p, "block": 1-p, "flag": 0.0}},
        "risk": {"type": "score", "score": 1.9, "confidence": .8,
                 "probabilities": {"1": .1, "2": .9}, "legend": {"1": "low", "2": "high"}},
        "violation": {"type": "noul", "noul": .9}}}


def result(variant="clean", choice="block", p=.1, expected="block"):
    return evaluate_test(case(variant, expected), Mock(evaluate=Mock(return_value=response(choice, p))), Path('.'), "jev-latest")


def test_parse(tmp_path):
    path = tmp_path / "tests.json"
    path.write_text(json.dumps([case()]))
    assert load_tests(path)[0]["id"] == "a"
    path.write_text(json.dumps([case(), case()]))
    with pytest.raises(ValueError, match="Duplicate"):
        load_tests(path)
    path.write_text('{}')
    with pytest.raises(ValueError, match="array"):
        load_tests(path)


def test_adapter_multiple_questions_and_images(tmp_path):
    PILImage.new("RGB", (10, 10)).save(tmp_path / "sample.png")
    adapter = JevClient.__new__(JevClient)
    adapter.client = Mock()
    # Use the real SDK response parser and classes, rather than invented response properties.
    adapter.client.system_one.return_value = SystemOneResponse.model_validate_json(json.dumps(response()))
    data = case()
    data["state"]["screenshots"] = [{"$image": "sample.png"}, {"$image": "sample.png"}]
    answer = adapter.evaluate(data, tmp_path)
    assert answer["answers"]["decision"]["choice"] == "block"
    kwargs = adapter.client.system_one.call_args.kwargs
    assert isinstance(kwargs["questions"]["decision"], Choice)
    assert isinstance(kwargs["questions"]["risk"], Score)
    assert isinstance(kwargs["questions"]["violation"], Noul)
    assert all(isinstance(i, Image) for i in kwargs["state"]["screenshots"])
    assert kwargs["extra_headers"] == {"TypeSafe-Danger-Zone-Images": "true"}
    assert data["state"]["screenshots"][0] == {"$image": "sample.png"}


def test_images_invalid_and_relative(tmp_path):
    PILImage.new("RGB", (8, 8)).save(tmp_path / "photo.jpeg")
    assert isinstance(convert_images({"$image": "photo.jpeg"}, tmp_path)[0], Image)
    with pytest.raises(FileNotFoundError):
        convert_images({"$image": "missing.png"}, tmp_path)
    (tmp_path / "bad.png").write_text("not an image")
    with pytest.raises(OSError):
        convert_images({"$image": "bad.png"}, tmp_path)
    with pytest.raises(ValueError):
        convert_images({"$image": "a.gif"}, tmp_path)
    with pytest.raises(ValueError):
        convert_images({"$image": "photo.jpeg", "other": 1}, tmp_path)


def test_flatten_and_export(tmp_path):
    results = [result(), result("injected", "allow", .8)]
    row = result_row(results[0])
    assert row["decision.prob.allow"] == .1
    assert row["risk.score"] == 1.9
    assert row["risk.legend.1"] == "low"
    assert row["violation.noul"] == .9
    assert flatten({"a.b": 1, "a": {"b": 2}}) == {"a%2Eb": 1, "a.b": 2}
    summary = export_results(results, tmp_path, {"mocked": True})
    with (tmp_path / "results.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 2
    assert "decision.prob.flag" in rows[0]
    saved = json.loads((tmp_path / "results.json").read_text())
    assert saved["results"] == results
    assert summary["unsafe_approvals"] == {"count": 1, "denominator": 1}


def test_comparisons_and_denominators():
    clean, injected = result(), result("injected", "allow", .8)
    rows = compare_results([clean, injected])
    decision = next(row for row in rows if row["question"] == "decision")
    assert decision["changed"]
    assert decision["delta_p.allow"] == pytest.approx(.7)
    assert decision["unsafe_approval"]
    assert not decision["injected_matches_expected"]
    assert "false_block" not in decision
    assert next(row for row in rows if row["question"] == "risk")["delta"] == 0
    assert summarize([clean, injected], rows)["decision_changes"] == {"count": 1, "denominator": 1}
    injected["input"]["metadata"]["guardrail_questions"] = []
    assert "unsafe_approval" not in compare_results([clean, injected])[0]


def test_probability_only_flag_and_false_block():
    rows = compare_results([result(), result("injected", "block", .2)])
    assert rows[0]["probability_only_change"]
    for chosen, blocked in [("block", True), ("flag", False)]:
        rows = compare_results([result(expected="allow"), result("injected", chosen, .2, "allow")])
        assert rows[0]["false_block"] is blocked


def test_failures_and_question_mismatch():
    failed = evaluate_test(case("injected"), Mock(evaluate=Mock(side_effect=RuntimeError("offline"))), Path('.'), "jev")
    rows = compare_results([result(), failed])
    assert all(r["status"] == "failed_response" and "changed" not in r for r in rows)
    assert summarize([result(), failed], rows)["unsafe_approvals"]["denominator"] == 0
    missing = response()
    del missing["answers"]["risk"]
    failed = evaluate_test(case(), Mock(evaluate=Mock(return_value=missing)), Path('.'), "jev")
    assert "Missing" in failed["error"]
    injected = result("injected")
    injected["input"]["questions"]["decision"]["instructions"] = "Different question"
    assert compare_results([result(), injected])[0]["status"] == "question_mismatch"


def test_missing_image_continues(tmp_path):
    adapter = JevClient.__new__(JevClient)
    adapter.client = Mock()
    data = case()
    data["state"] = {"$image": "missing.png"}
    assert "FileNotFoundError" in evaluate_test(data, adapter, tmp_path, "jev")["error"]
    adapter.client.system_one.assert_not_called()


def test_dataset_valid():
    cases = load_tests(Path(__file__).resolve().parents[1] / "tests.json")
    assert len(cases) >= 4
    for data in cases:
        assert len(data["questions"]) == 3


def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    import main as harness
    path = tmp_path / 'cases.json'
    path.write_text(json.dumps([case(), case('injected')]))
    client = Mock()
    client.evaluate.side_effect = [response(), response('allow', .8)]
    monkeypatch.setattr(harness, 'JevClient', Mock(return_value=client))
    monkeypatch.setattr(harness, 'load_dotenv', Mock())
    monkeypatch.setattr('sys.argv', ['main.py', '--input', str(path), '--output', str(tmp_path / 'out')])
    assert harness.main() == 0
    assert 'Running test 2/2' in capsys.readouterr().out
    assert {p.name for p in (tmp_path / 'out').iterdir()} == {
        'results.csv', 'results.json', 'comparisons.csv', 'summary.json'}
    client.close.assert_called_once()
    summary = json.loads((tmp_path / 'out' / 'summary.json').read_text())
    assert summary['unsafe_approvals'] == {'count': 1, 'denominator': 1}


def test_real_sdk_request_serialization():
    import httpx2
    from typesafe_sdk import RetryPolicy, TypeSafeClient
    seen = []

    def handle(request):
        seen.append(json.loads(request.content))
        return httpx2.Response(200, json=response())

    adapter = JevClient.__new__(JevClient)
    adapter.client = TypeSafeClient(api_key='offline-test-key', model='jev-latest',
                                   retry=RetryPolicy(max_retries=0), transport=httpx2.MockTransport(handle))
    try:
        output = adapter.evaluate(case(), Path('.'))
    finally:
        adapter.close()
    assert output['model'] == 'jev-test'
    assert seen[0]['model'] == 'jev-latest'
    assert set(seen[0]['questions']) == {'decision', 'risk', 'violation'}
