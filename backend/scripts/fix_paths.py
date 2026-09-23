"""Fix domain.py to read runtime data from models/ instead of data/"""
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

# 1. Patch domain.py paths
domain_py = BASE / "engines" / "domain.py"
content = domain_py.read_text(encoding="utf-8")

old = (
    'BASE_DIR       = Path(__file__).resolve().parent.parent\n'
    'DATA_DIR       = BASE_DIR / "data"\n'
    'SPF_DB_PATH    = DATA_DIR / "spf_dmarc_cache.db"\n'
    'URLHAUS_PATH   = DATA_DIR / "urlhaus_domains.txt"\n'
    'PHISHTANK_PATH = DATA_DIR / "phishtank_domains.txt"'
)
new = (
    'BASE_DIR       = Path(__file__).resolve().parent.parent\n'
    'DATA_DIR       = BASE_DIR / "data"\n'
    'MODELS_DIR     = BASE_DIR / "models"\n'
    '# Runtime lookup files live in models/ -- tracked in git, available on Render\n'
    'SPF_DB_PATH    = MODELS_DIR / "spf_dmarc_cache.db"\n'
    'URLHAUS_PATH   = MODELS_DIR / "urlhaus_domains.txt"\n'
    'PHISHTANK_PATH = MODELS_DIR / "phishtank_domains.txt"'
)

if old in content:
    domain_py.write_text(content.replace(old, new), encoding="utf-8")
    print("[OK] domain.py paths updated -> models/")
else:
    print("[WARN] domain.py pattern not found - already patched?")
    idx = content.find("SPF_DB_PATH")
    print(repr(content[max(0,idx-50):idx+120]))

# 2. Copy runtime data files to models/ (so they are tracked in git)
models_dir = BASE / "models"
data_dir   = BASE / "data"

copies = [
    ("urlhaus_domains.txt", "urlhaus_domains.txt"),
    ("spf_dmarc_cache.db",  "spf_dmarc_cache.db"),
]

for src_name, dst_name in copies:
    src = data_dir / src_name
    dst = models_dir / dst_name
    if src.exists():
        shutil.copy2(src, dst)
        print(f"[OK] Copied {src_name} -> models/ ({dst.stat().st_size // 1024} KB)")
    elif dst.exists():
        print(f"[OK] {dst_name} already in models/ ({dst.stat().st_size // 1024} KB)")
    else:
        print(f"[WARN] {src_name} not found in data/ or models/")

print("\nDone.")
