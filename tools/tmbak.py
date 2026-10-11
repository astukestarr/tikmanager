"""Open a TikManager off-site backup (.tmbak) - decrypt it with its passphrase and unpack it.

    python3 tools/tmbak.py tikmanager-20261011-030000-full.tmbak restore-folder
      (asks for the passphrase; needs python3-cryptography, which every TikManager server has)

A full backup unpacks to: tikmanager.db, master.key, tikmanager.env, branding/, scripts.json and manifest.json. To
rebuild a server from it, see "Restoring from an off-site backup" in the README. A scripts-only backup without a
passphrase is plain JSON and needs no tool.
"""
import getpass
import io
import json
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from offsite import OffsiteError, decrypt  # noqa: E402


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    try:
        data = decrypt(src.read_bytes(), getpass.getpass("Passphrase: "))
    except OffsiteError as e:
        sys.exit(str(e))
    out.mkdir(parents=True, exist_ok=True)
    if data[:1] == b"{":   # scripts only
        (out / "scripts.json").write_bytes(data)
        print(f"Scripts written to {out / 'scripts.json'}")
        return
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tar.extractall(out, filter="data")   # refuses absolute paths / .. / links outside the folder
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    print(f"Unpacked a {m.get('what')} backup of TikManager {m.get('version')} from {m.get('host')} into {out}:")
    for p in sorted(out.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(out)}")


if __name__ == "__main__":
    main()
