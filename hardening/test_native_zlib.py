"""Exercise the exact distro-patched zlib, including bounded gz* write-error recovery.

The error-path controls are regression coverage, not a claimed exploit reproducer.
All native calls run in isolated, time/memory-bounded child processes.
"""

import hashlib
from pathlib import Path
import subprocess
import sys

import pytest


def test_exact_security_backport_is_installed_and_loaded():
    assert hashlib.sha256(Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3.1").read_bytes()).hexdigest() == (
        "6c13931760210e8b391b63a337dfe4071346c4ad6e3827694edb7b6989bb16dd"
    )
    package = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", "zlib1g"], text=True)
    assert package == "1:1.3.dfsg+really1.3.1-1+deb13u1"


@pytest.mark.parametrize("size", [32, 512, 16384, 65536])
@pytest.mark.parametrize("failed_write", [False, True])
def test_gz_write_valid_output_and_error_recovery(size, failed_write, tmp_path):
    script = r"""
import ctypes, gzip, os, pathlib, resource, sys
resource.setrlimit(resource.RLIMIT_AS,(128*1024**2,128*1024**2))
resource.setrlimit(resource.RLIMIT_CPU,(3,3))
lib=ctypes.CDLL('libz.so.1')
lib.gzdopen.argtypes=[ctypes.c_int,ctypes.c_char_p];lib.gzdopen.restype=ctypes.c_void_p
lib.gzwrite.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint];lib.gzwrite.restype=ctypes.c_int
lib.gzflush.argtypes=[ctypes.c_void_p,ctypes.c_int];lib.gzflush.restype=ctypes.c_int
lib.gzclearerr.argtypes=[ctypes.c_void_p]
lib.gzclose.argtypes=[ctypes.c_void_p];lib.gzclose.restype=ctypes.c_int
size=int(sys.argv[1]);failed=sys.argv[2]=='True';target=pathlib.Path(sys.argv[3])
if failed:
 reader,fd=os.pipe();os.close(reader)
else:
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
stream=lib.gzdopen(fd,b'wb');assert stream
expected=[]
try:
 for index in range(4):
  payload=bytes((i*31+index)%256 for i in range(size));buffer=ctypes.create_string_buffer(payload)
  result=lib.gzwrite(stream,buffer,len(payload))
  flushed=lib.gzflush(stream,2)
  if failed:
   assert result in (0,len(payload)) and flushed in (-1,-5)
   lib.gzclearerr(stream)
  else:
   assert result==len(payload) and flushed==0;expected.append(payload)
finally:
 closed=lib.gzclose(stream)
if not failed:
 assert closed==0
 assert gzip.decompress(target.read_bytes())==b''.join(expected)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(size), str(failed_write), str(tmp_path / "control.gz")],
        capture_output=True,
        text=True,
        timeout=6,
        check=False,
    )
    assert result.returncode == 0, result.stderr
