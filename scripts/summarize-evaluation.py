"""Build thesis tables and figures from the raw experiment runs."""
import argparse
import csv
from collections import defaultdict
import json
import math
from pathlib import Path
import statistics

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


CRYPTO_METRICS = ('issueMs', 'deriveMs', 'holderSignMs', 'verifyVcMs', 'verifyVpMs',
                  'baseBytes', 'vcBytes', 'vpBytes', 'vcProofBytes', 'vpProofBytes')
HTTP_METRICS = ('e2eMs', 'requestMs', 'previewMs', 'presentMs', 'walletDeriveMs',
                'walletSignMs', 'verifierCryptoMs', 'verifierStatusMs', 'verifierRedisMs', 'postBodyBytes')
LABELS = {
    'recruitment': 'Tuyển dụng', 'scholarship': 'Học bổng',
    'course': 'Chứng chỉ', 'legacy': 'Bằng lịch sử',
}


def load(folder):
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    rows = [json.loads(line) for line in (folder / 'samples.jsonl').read_text(encoding='utf-8').splitlines()]
    if not manifest.get('completedAt'):
        print(f'Run did not complete: {folder}')
    return manifest, rows


def describe(rows, metrics):
    result = {}
    for metric in metrics:
        values = sorted(row[metric] for row in rows if row['ok'] and row.get(metric) is not None)
        if values:
            result[metric] = {
                'n': len(values), 'median': statistics.median(values),
                'p95': values[math.ceil(0.95 * len(values)) - 1],
                'sd': statistics.stdev(values) if len(values) > 1 else None,
            }
    return result


def create_figures(disclosure, latency, crypto, output):
    scenarios = list(disclosure)
    labels = [LABELS[name] for name in scenarios]
    x = list(range(len(labels)))
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), layout='constrained')
    for offset, mode, label, color in [(-0.18, 'full', 'Tiết lộ đầy đủ', '#607286'),
                                       (0.18, 'sd', 'ECDSA-SD', '#168477')]:
        positions = [i + offset for i in x]
        axes[0].bar(positions, [disclosure[name][mode]['count'] for name in scenarios], .34, label=label, color=color)
        axes[1].bar(positions, [crypto[name][mode]['stats']['vpBytes']['median'] for name in scenarios],
                    .34, label=label, color=color)
    axes[0].set_ylabel('Số thuộc tính nghiệp vụ gửi đi')
    axes[1].set_ylabel('Kích thước VP trung vị (byte)')
    for axis in axes:
        axis.set_xticks(x, labels, rotation=12)
        axis.legend()
        axis.grid(axis='y', alpha=.25)
        axis.set_axisbelow(True)
    fig.savefig(output / 'disclosure-size.png', dpi=180)
    plt.close(fig)
    if latency:
        fig, axis = plt.subplots(figsize=(7, 4.2), layout='constrained')
        levels = list(latency)
        for statistic, label in [('median', 'Trung vị'), ('p95', 'p95')]:
            axis.plot(list(range(len(levels))), [latency[level]['stats']['e2eMs'][statistic] for level in levels],
                      marker='o', label=label)
        axis.set_xticks(list(range(len(levels))), levels)
        axis.set(xlabel='Số phiên gửi đồng thời', ylabel='Độ trễ toàn luồng xác minh (ms)', ylim=(0, None))
        axis.grid(alpha=.25)
        axis.legend()
        fig.savefig(output / 'http-latency.png', dpi=180)
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('raw', type=Path, help='Root containing session-*/crypto and optionally stack/http')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    crypto_rows, http_rows, manifests = [], [], []
    for path in sorted(args.raw.glob('session-*/crypto/manifest.json')):
        manifest, rows = load(path.parent)
        manifests.append(manifest)
        crypto_rows.extend(row for row in rows if row['round'] >= 0)
    http_path = args.raw / 'stack' / 'http'
    if (http_path / 'manifest.json').exists():
        manifest, http_rows = load(http_path)
        manifests.append(manifest)
    if not crypto_rows:
        parser.error('No measured crypto samples found')
    keys = {(m['commit'], m['lockSha256']) for m in manifests}
    if len(keys) != 1:
        parser.error('Runs must come from a single source revision and lockfile')
    sessions = [m['config']['session'] for m in manifests if m['kind'] == 'crypto']
    if len(sessions) != len(set(sessions)):
        parser.error('Duplicate crypto session IDs')

    grouped = defaultdict(list)
    for row in crypto_rows:
        grouped[row['scenario'], row['mode']].append(row)
    crypto, disclosure, http = {}, {}, {}
    table = ['# Bảng tổng hợp thực nghiệm', '',
             '| Kịch bản | Phương án | Đạt/tổng | Issue | Derive | Ký VP | Xác minh VC | Xác minh VP | Base VC (B) | VC gửi (B) | VP (B) |',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']

    def fmt(data, name):
        stat = data.get(name)
        if not stat:
            return '—'
        return f"{stat['median']:.2f} / {stat['p95']:.2f}" if name.endswith('Ms') else f"{stat['median']:g}"

    for scenario in LABELS:
        for mode in ('full', 'sd'):
            rows = grouped[scenario, mode]
            stats = describe(rows, CRYPTO_METRICS)
            valid = [row for row in rows if row['ok']]
            if not valid:
                parser.error(f'No successful samples for {scenario}/{mode}')
            record = valid[0]
            signatures = {(tuple(row['disclosed']), tuple(row['total'])) for row in valid}
            if len(signatures) != 1:
                parser.error(f'Unexpected variation of field sets for {scenario}/{mode}')
            disclosure.setdefault(scenario, {})[mode] = {
                'count': len(record['disclosed']), 'total': len(record['total']),
                'disclosed': record['disclosed'], 'hidden': record['hidden'], 'visibleMetadata': record['visibleMetadata'],
            }
            by_session = {session: describe([r for r in rows if r['session'] == session], CRYPTO_METRICS)
                          for session in sessions}
            crypto.setdefault(scenario, {})[mode] = {
                'n': len(rows), 'success': len(valid), 'stats': stats, 'bySession': by_session,
            }
            summary = ' | '.join(fmt(stats, metric) for metric in CRYPTO_METRICS[:8])
            table.append(f'| {LABELS[scenario]} | {mode} | {len(valid)}/{len(rows)} | {summary} |')

    table.extend(['', 'Thời gian tính bằng ms, trung vị / p95. Kích thước là trung vị số byte JSON UTF-8.', '',
                  '| Kịch bản | Đầy đủ | ECDSA-SD | Giảm thuộc tính nghiệp vụ |',
                  '|---|---:|---:|---:|'])
    for scenario, values in disclosure.items():
        full, sd = values['full']['count'], values['sd']['count']
        table.append(f'| {LABELS[scenario]} | {full}/{full} | {sd}/{full} | {(1 - sd/full):.1%} |')

    measured_http = [row for row in http_rows if row['phase'] == 'measured']
    if measured_http:
        table.extend(['', '| Phiên đồng thời | Đạt/tổng | E2E | Tạo yêu cầu | Xem trước | Trình bày và xác minh |',
                      '|---:|---:|---:|---:|---:|---:|'])
    for parallel in sorted({row['parallel'] for row in measured_http}):
        rows = [row for row in measured_http if row['parallel'] == parallel]
        stats = describe(rows, HTTP_METRICS)
        success = sum(row['ok'] for row in rows)
        http[parallel] = {'n': len(rows), 'success': success, 'stats': stats}
        summary = ' | '.join(fmt(stats, metric) for metric in HTTP_METRICS[:4])
        table.append(f'| {parallel} | {success}/{len(rows)} | {summary} |')
    (args.output / 'tables.md').write_text('\n'.join(table) + '\n', encoding='utf-8')
    summary = {'manifests': manifests, 'disclosure': disclosure, 'crypto': crypto, 'http': http,
               'httpSetupAndFirst': [r for r in http_rows if r['phase'] in ('setup', 'first')]}
    (args.output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for name, rows in [('crypto', crypto_rows), ('http', http_rows)]:
        if not rows:
            continue
        fields = list(dict.fromkeys(key for row in rows for key in row))
        with (args.output / f'{name}.csv').open('w', newline='', encoding='utf-8-sig') as stream:
            writer = csv.DictWriter(stream, fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    create_figures(disclosure, http, crypto, args.output)


if __name__ == '__main__':
    main()
