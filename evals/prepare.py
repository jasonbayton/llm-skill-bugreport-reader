#!/usr/bin/env python3
"""Prepare diagnosis requests with a rubric-free copy of the skill."""
import argparse
import json
import re
import shutil
from pathlib import Path


# Copy only resources used for diagnosis. Tests can reveal expected outcomes too.
SKILL_FILES = ('SKILL.md', 'README.md')
SKILL_DIRECTORIES = ('scripts', 'references', 'agents', 'assets')
EXCLUDED = shutil.ignore_patterns('evals', 'tests', '__pycache__', '*.pyc', '.git')


def evaluator_document(text: str) -> str:
    """Remove development-only pointers from the evaluator's document copy."""
    return '\n'.join(line for line in text.splitlines()
                     if not re.search(r'evals/|tests/|unittest|rubric|diagnosis scenarios', line, re.I)) + '\n'


def copy_skill(source: Path, destination: Path) -> None:
    resources = [source / name for name in SKILL_FILES + SKILL_DIRECTORIES]
    for resource in resources:
        if resource.is_symlink() or (resource.is_dir() and any(p.is_symlink() for p in resource.rglob('*'))):
            raise ValueError('Skill resources must not contain symlinks to external material')
    destination.mkdir()
    for resource in resources:
        if resource.is_dir():
            shutil.copytree(resource, destination / resource.name, ignore=EXCLUDED)
        elif resource.is_file():
            (destination / resource.name).write_text(evaluator_document(resource.read_text()))


def prepare(skill: Path, output: Path) -> int:
    skill = skill.resolve()
    output = output.resolve()
    if output.exists():
        raise ValueError('--out must be a new directory')
    if not (skill / 'SKILL.md').is_file():
        raise ValueError('--skill must contain SKILL.md')
    if skill == output or skill in output.parents:
        raise ValueError('--out must be outside the source skill')

    evaluation_source = Path(__file__).resolve().parent
    cases = json.loads((evaluation_source / 'cases.json').read_text())
    output.mkdir(parents=True)
    isolated_skill = output / 'skill'
    copy_skill(skill, isolated_skill)
    requests = []
    for number, case in enumerate(cases, 1):
        case_directory = output / f'case-{number:03d}'
        case_directory.mkdir()
        artifact = case_directory / 'report.txt'
        shutil.copyfile(evaluation_source / case['fixture'], artifact)
        prompt = (
            f'Use the skill at {isolated_skill}/SKILL.md to answer this request. '
            'Read only this copied skill and the supplied artifact. '
            'Work read-only against the artifact, writing any outputs only to '
            f'{case_directory}.\n\n{case["prompt"]}\n\nReport: {artifact}\n'
        )
        (case_directory / 'request.txt').write_text(prompt)
        requests.append({'id': case['id'], 'prompt': prompt, 'artifact': str(artifact)})
    (output / 'requests.json').write_text(json.dumps(requests, indent=2) + '\n')
    return len(requests)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skill', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        count = prepare(args.skill, args.out)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f'Prepared {count} requests using a copied skill; no tests, evals or rubrics copied')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
