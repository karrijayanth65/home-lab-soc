"""Offline capstone assurance: evidence integrity, detection and response closure gates."""
from pathlib import Path
import argparse
import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('case14', ROOT / 'tests/case14/test_case14_correlation.py')
CHAIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHAIN)


def validate(record, manifest, blobs):
    errors = []
    for item in manifest['artifacts']:
        content = blobs.get(item['path'])
        if content is None or hashlib.sha256(content).hexdigest() != item['sha256']:
            errors.append('integrity:' + item['path'])
    if record['mode'] != 'offline_simulation':
        errors.append('unsupported_evidence_mode')
    grouped = {}
    for event in record['events']:
        grouped.setdefault((event['host'], event['user']), []).append(event)
    detected = []
    for key, events in grouped.items():
        matched, _, _ = CHAIN.correlate(events, CHAIN.STAGES, 1800)
        if matched:
            detected.append(list(key))
    if sorted(detected) != sorted(record['expected_scope']):
        errors.append('scope_or_detection_mismatch')
    stages = ['preserve', 'triage', 'scope', 'contain', 'eradicate', 'recover', 'hunt', 'review']
    actions = record['actions']
    if [a['stage'] for a in actions] != stages:
        errors.append('response_order')
    times = [datetime.fromisoformat(a['time'].replace('Z', '+00:00')) for a in actions]
    if any(a >= b for a, b in zip(times, times[1:])):
        errors.append('response_timestamps')
    if not all(a.get('owner') and a.get('acceptance') and a.get('evidence') for a in actions):
        errors.append('incomplete_action_record')
    if any(ref not in blobs for a in actions for ref in a.get('evidence', [])):
        errors.append('missing_action_evidence')
    for check in ('host_isolated', 'account_restricted', 'task_absent', 'artifact_quarantined',
                  'telemetry_healthy', 'service_healthy', 'owner_approved', 'residual_hunt_complete'):
        if record['recovery'].get(check) is not True:
            errors.append('recovery:' + check)
    if record['recovery']['residual_matches'] != 0:
        errors.append('residual_activity')
    if not record['recovery']['observation_minutes'] >= 60:
        errors.append('observation_window')
    return errors, detected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='tests/case15/results.json')
    args = parser.parse_args()
    base = ROOT / 'investigations/Case 15 - SOC Incident Response Capstone/evidence'
    record = json.loads((base / 'exercise.json').read_text())
    manifest = json.loads((base / 'manifest.json').read_text())
    blobs = {a['path']: (ROOT / a['path']).read_bytes() for a in manifest['artifacts']}
    cases = []

    def run(name, candidate, data, expected):
        errors, detected = validate(candidate, manifest, data)
        cases.append({'id': name, 'expected_accept': expected, 'actual_accept': not errors,
                      'passed': (not errors) == expected, 'errors': errors, 'detected_scope': detected})

    run('complete_exercise', record, blobs, True)
    tampered = dict(blobs)
    tampered[next(iter(tampered))] += b'altered'
    run('altered_evidence_blocks_closure', record, tampered, False)
    missing = dict(blobs)
    missing.pop(next(iter(missing)))
    run('missing_evidence_blocks_closure', record, missing, False)
    for field in ('task_absent', 'telemetry_healthy', 'owner_approved', 'residual_hunt_complete'):
        candidate = copy.deepcopy(record)
        candidate['recovery'][field] = False
        run(field + '_required', candidate, blobs, False)
    candidate = copy.deepcopy(record)
    candidate['recovery']['residual_matches'] = 1
    run('recurrence_blocks_closure', candidate, blobs, False)
    candidate = copy.deepcopy(record)
    candidate['recovery']['observation_minutes'] = 15
    run('short_observation_blocks_closure', candidate, blobs, False)
    candidate = copy.deepcopy(record)
    candidate['actions'][0], candidate['actions'][3] = candidate['actions'][3], candidate['actions'][0]
    run('late_preservation_blocks_closure', candidate, blobs, False)
    candidate = copy.deepcopy(record)
    candidate['expected_scope'] = [['WIN11-LAB-02', 'lab-admin']]
    run('incorrect_scope_blocks_closure', candidate, blobs, False)
    candidate = copy.deepcopy(record)
    candidate['events'] = [e for e in candidate['events'] if CHAIN.classify(e) != 'file_decode']
    run('incomplete_chain_blocks_validation', candidate, blobs, False)
    report = {'mode': 'offline_simulation', 'executed_at_utc': datetime.now(timezone.utc).isoformat(),
              'passed': all(c['passed'] for c in cases),
              'tests_total': len(cases), 'tests_passed': sum(c['passed'] for c in cases),
              'artifact_count': len(manifest['artifacts']), 'results': cases}
    (ROOT / args.output).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'results'}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
