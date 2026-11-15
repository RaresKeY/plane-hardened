#!/usr/bin/env python3
"""Inventory and scan an exact built backend artifact offline on qualified Debian host.

Requires already-qualified standalone tools and the imported 2026-11-15 Grype DB.
This records findings; a zero scanner exit code does not mean no vulnerabilities.
"""

import argparse
import os
from pathlib import Path
import re
import subprocess

from operator_config import operator_config


REMOTE = r"""
import collections, hashlib, json, pathlib, subprocess, uuid
base=pathlib.Path(BASE)
root=base/('security-scan-'+IMAGE[:12]+'-'+uuid.uuid4().hex[:6]);root.mkdir(mode=0o700)
out=root/'out';out.mkdir()
(root/'native_inventory.py').write_text(INVENTORY)
database=base/'security-scan-50670/database.tar.zst'
with database.open('rb') as handle:
 digest=hashlib.file_digest(handle,'sha256').hexdigest()
 assert digest=='96ada30f3287fd04be595a8f419df98efdf19955e7bfa28eae80ef7c5fe27eb7'
db=root/'db';db.mkdir()
def run(command, log, name=None):
 try:
  with log.open('w') as handle:
   result=subprocess.run(command,stdout=handle,stderr=subprocess.STDOUT,timeout=900)
  (log.with_suffix('.command.json')).write_text(json.dumps({'command':command,'exit_code':result.returncode}))
  if result.returncode:raise RuntimeError(log.read_text()[-2000:])
 finally:
  if name:subprocess.run(['podman','rm','-f',name],capture_output=True,check=False)
def container(tool,args,mounts,environment=None):
 name='plane-qualification-scan-'+uuid.uuid4().hex[:10]
 cmd=['podman','run','--rm','--name',name,'--label','io.rareskey.project=plane-hardened',
      '--label','io.rareskey.retention=ephemeral','--network=none','--read-only',
      '--userns=keep-id:uid=1000,gid=1000','--user=1000:1000','--cap-drop=ALL',
      '--security-opt=no-new-privileges','--memory=3g','--cpus=1','--pids-limit=128',
      '--tmpfs','/tmp:rw,nosuid,nodev,size=512m','--env','HOME=/tmp']
 for value in mounts:cmd+=['--volume',value]
 for key,value in (environment or {}).items():cmd+=['--env',key+'='+value]
 return cmd+['--entrypoint='+tool,IMAGE,*args],name
run(['podman','save','--format=oci-archive','--output',str(root/'backend.oci.tar'),IMAGE],out/'export.log')
(root/'artifact.json').write_text(json.dumps({'image':IMAGE,'archive_sha256':hashlib.sha256((root/'backend.oci.tar').read_bytes()).hexdigest()}))
mounts=[str(root)+':/input:ro',str(out)+':/out:rw',str(base/'tools')+':/tools:ro']
cmd,name=container('/opt/venv/bin/python',['/input/native_inventory.py'],mounts)
run(cmd,out/'native-inventory.json',name)
cmd,name=container('/tools/syft',['oci-archive:/input/backend.oci.tar','-o','syft-json=/out/backend-sbom.json',
                              '-o','cyclonedx-json=/out/backend-cdx.json'],mounts,{'SYFT_CHECK_FOR_APP_UPDATE':'false'})
run(cmd,out/'syft.log',name)
cmd,name=container('/tools/grype',['db','import','/database.tar.zst'],
                   mounts+[str(db)+':/db:rw',str(database)+':/database.tar.zst:ro'],
                   {'GRYPE_CHECK_FOR_APP_UPDATE':'false','GRYPE_DB_AUTO_UPDATE':'false','GRYPE_DB_CACHE_DIR':'/db'})
run(cmd,out/'grype-import.log',name)
cmd,name=container('/tools/grype',['sbom:/out/backend-sbom.json','-o','json','--file','/out/backend-grype.json'],
                   mounts+[str(db)+':/db:ro'],{'GRYPE_CHECK_FOR_APP_UPDATE':'false','GRYPE_DB_AUTO_UPDATE':'false','GRYPE_DB_CACHE_DIR':'/db'})
run(cmd,out/'grype.log',name)
report=json.loads((out/'backend-grype.json').read_text());matches=report['matches']
summary={'image':IMAGE,'directory':str(root),'matches':len(matches),
         'advisory_ids':len({m['vulnerability']['id'] for m in matches}),
         'by_severity':dict(collections.Counter(m['vulnerability']['severity'] for m in matches)),
         'database':report.get('descriptor',{}).get('db',{}),
         'limits':['Version matching is not reachability analysis',
                   'Scanner success is not a finding-disposition gate',
                   'No network, exploit probe or VPS action']}
(out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="Exact qualified backend image SHA256")
    args = parser.parse_args()
    operator = operator_config(parser)
    if not re.fullmatch(r"[0-9a-f]{64}", args.image):
        parser.error("An exact 64-character backend image SHA256 is required")
    if not os.environ.get("SSH_AUTH_SOCK"):
        parser.error("Reuse the dedicated session SSH agent")
    inventory = Path(__file__).with_name("native_inventory.py").read_text()
    script = (
        "BASE=" + repr(operator.root) + "\nIMAGE=" + repr(args.image) + "\nINVENTORY=" + repr(inventory) + "\n" + REMOTE
    )
    subprocess.run(
        operator.ssh + ["python3 -"],
        input=script,
        text=True,
        check=True,
    )


if __name__ == "__main__":
    main()
