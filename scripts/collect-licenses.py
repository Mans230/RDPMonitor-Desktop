"""Collect actual build-environment Python distribution notices for release audit."""
import argparse
import importlib.metadata
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sections = ['RDPMonitor bundled Python dependency notices', f'Python runtime: {sys.version}',
                'Python Software Foundation license: https://docs.python.org/3/license.html',
                'Flutter/native plugin notices are bundled in client/data/flutter_assets/NOTICES.Z.']
    for package in sorted(importlib.metadata.distributions(), key=lambda item: item.metadata.get('Name', '').lower()):
        name = package.metadata.get('Name', 'unknown')
        sections += ['\n' + '=' * 78, f'{name} {package.version}',
                     'License metadata: ' + (package.metadata.get('License-Expression') or package.metadata.get('License') or 'See included distribution license files'),
                     'Project: ' + (package.metadata.get('Home-page') or '')]
        for filename in package.files or []:
            lower = str(filename).lower()
            if 'dist-info/' not in lower and 'egg-info/' not in lower:
                continue
            if any(part in Path(lower).name for part in ('license', 'copying', 'notice')):
                path = package.locate_file(filename)
                if path.is_file():
                    sections += [f'\n--- {name}: {filename} ---', path.read_text(encoding='utf-8', errors='replace')]
    args.output.write_text('\n'.join(sections) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
