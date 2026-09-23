import zipfile, pathlib

base_dir = pathlib.Path(__file__).parent.parent
corpus = base_dir / 'data' / 'synthetic_corpus'
out = base_dir / 'data' / 'mode2_demo.zip'
emls = sorted(corpus.glob('*.eml'))

with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for f in emls:
        z.write(f, f.name)

print(f"Created {out} with {len(emls)} files ({out.stat().st_size // 1024} KB)")

for name in ['email_01_C1.eml', 'email_16_C2.eml', 'email_31_C3.eml', 'email_46_NOISE.eml']:
    content = (corpus / name).read_text(encoding='utf-8', errors='ignore')
    lines = content.splitlines()
    subject = next((l for l in lines if l.startswith('Subject:')), 'Subject: ?')
    frm = next((l for l in lines if l.startswith('From:')), 'From: ?')
    print(f"{name}:")
    print(f"  {frm.strip()}")
    print(f"  {subject.strip()}")
