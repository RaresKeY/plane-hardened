"""Transfer a manifest-bound source snapshot from the owning checkout, without ignored secrets."""

import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile


REVIEWED_SYMLINKS = {"packages/i18n/locales": "src/locales"}


def stage(repo, destination, ssh):
    names = (
        subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=repo)
        .decode()
        .split("\0")
    )
    manifest = {}
    total = 0
    with tempfile.TemporaryFile() as archive:
        with tarfile.open(fileobj=archive, mode="w") as output:
            for name in sorted(set(filter(None, names))):
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts or relative.parts[0] in (".git", ".local"):
                    raise ValueError("Unsafe source snapshot path")
                if (
                    relative.name == ".env"
                    or relative.name.startswith(".env.")
                    and not relative.name.endswith(".example")
                ):
                    raise ValueError("Private environment file must not enter source snapshot")
                path = repo / relative
                if path.is_symlink():
                    link = os.readlink(path)
                    if REVIEWED_SYMLINKS.get(name) != link or not path.resolve().is_relative_to(repo.resolve()):
                        raise ValueError("Review source symlink before qualification: " + name)
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.SYMTYPE
                    info.linkname = link
                    info.mode = 0o755
                    output.addfile(info)
                    manifest[name] = hashlib.sha256(("SYMLINK:" + link).encode()).hexdigest()
                    continue
                if not path.resolve().is_relative_to(repo.resolve()):
                    raise ValueError("Source path resolves outside the owning checkout")
                if not path.is_file():
                    continue
                if path.stat().st_size > 100 * 1024**2:
                    raise ValueError("Source file exceeds reviewed size bounds")
                data = path.read_bytes()
                total += len(data)
                if len(data) > 100 * 1024**2 or total > 512 * 1024**2:
                    raise ValueError("Source snapshot exceeds reviewed size bounds")
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                output.addfile(info, io.BytesIO(data))
                manifest[name] = hashlib.sha256(data).hexdigest()
        archive.seek(0)
        receiver = """import sys,tarfile,pathlib,hashlib,json
root=pathlib.Path(DESTINATION)
root.mkdir(parents=True,mode=0o700,exist_ok=False)
manifest={};total=0
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
 for member in archive:
  path=pathlib.Path(member.name)
  assert not path.is_absolute() and '..' not in path.parts
  if member.issym():
   assert member.name=='packages/i18n/locales' and member.linkname=='src/locales'
   target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to(member.linkname)
   manifest[member.name]=hashlib.sha256(('SYMLINK:'+member.linkname).encode()).hexdigest()
   continue
  assert member.isfile() and not any(parent.is_symlink() for parent in (root/path).parents)
  assert member.size<=100*1024**2 and len(manifest)<20000
  total+=member.size;assert total<=512*1024**2
  data=archive.extractfile(member).read();assert len(data)==member.size
  target=root/path;target.parent.mkdir(parents=True,exist_ok=True)
  target.write_bytes(data);target.chmod(member.mode & 0o755)
  manifest[member.name]=hashlib.sha256(data).hexdigest()
root.with_suffix('.manifest.json').write_text(json.dumps(manifest,sort_keys=True))
print(hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest())
""".replace("DESTINATION", repr(destination))
        actual = subprocess.check_output(ssh + ["python3 -c " + shlex.quote(receiver)], stdin=archive).decode().strip()
    expected = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    if actual != expected:
        raise ValueError("Remote source snapshot digest mismatch")
    return expected
