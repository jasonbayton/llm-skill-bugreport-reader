#!/usr/bin/env python3
"""Prepare isolated diagnosis requests without exposing answer rubrics."""
import argparse,json,shutil
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--skill',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
base=Path(__file__).resolve().parent;skill=a.skill.resolve();out=a.out.resolve()
if out.exists():p.error('--out must be a new directory')
if not (skill/'SKILL.md').is_file():p.error('--skill must contain SKILL.md')
out.mkdir(parents=True);requests=[]
for c in json.loads((base/'cases.json').read_text()):
 directory=out/c['id'];directory.mkdir();artifact=directory/'report.txt';shutil.copyfile(base/c['fixture'],artifact)
 prompt=f"Use the skill at {skill}/SKILL.md to answer this request. Read only that skill's instructions/helpers/references and the supplied artifact; do not read its evals, rubrics or prior outputs. Work read-only against the artifact, writing any outputs only to {directory}.\n\n{c['prompt']}\n\nReport: {artifact}\n"
 (directory/'request.txt').write_text(prompt);requests.append({'id':c['id'],'prompt':prompt,'artifact':str(artifact)})
(out/'requests.json').write_text(json.dumps(requests,indent=2));print(f'Prepared {len(requests)} requests; no answers or rubrics copied')
