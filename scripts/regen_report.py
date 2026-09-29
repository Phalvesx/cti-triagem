"""Regenera, a partir do relatório e do código: report/HUNTING_PLAYBOOK.md, report/attack_layer_phexia.json
e scripts/mac_triage.sh (script DFIR de macOS com os IoCs do relatório)."""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.attack import scan_to_layer
from app.dfir import render_script
from app.hunting import build_hunt_pack, hunt_pack_markdown

H = "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e"
ROOT = Path(__file__).resolve().parents[1]
rep = ROOT / "report/RELATORIO_CTI.md"
t = rep.read_text(encoding="utf-8")
sec4 = t[t.index("## 4. TTPs"):t.index("## 5. Recomendações")]
techs = [{"id": m.group(3), "name": m.group(2).strip(), "tactic": m.group(1).strip()}
         for m in re.finditer(r"^\| ([A-Za-z &]+?) \| (.+?) \| (T\d{4}(?:\.\d{3})?) \|", sec4, re.M)]
scan = {"hash": H, "scan_id": 0, "engine": "relatório CTI", "created_at": "2026-09-24",
        "features": {"meta": {"names": ["gfskjsnghdjsvuxj", "UserInformation.txt"]}},
        "triage": {"verdict": "malicious", "malware_family": "Phexia", "platform": "macOS", "mitre_attack": techs,
                   "iocs": {"domains": ["ad4rchr39w8f.fun", "kys.li", "nfs8u9aw.shop"], "ips": [],
                            "urls": ["https://t.me/phefuckxiabot", "https://steamcommunity.com/id/phefuckxia"],
                            "abused_services": ["steamcommunity.com", "t.me"]}}}
layer = scan_to_layer(scan)
layer["name"] = "Phexia — TTPs do relatório CTI"
layer["description"] = f"Técnicas ATT&CK mapeadas no relatório CTI-2026-0924-PHEXIA (hash de referência {H})."
(ROOT / "report/attack_layer_phexia.json").write_text(json.dumps(layer, ensure_ascii=False, indent=2), encoding="utf-8")
md = hunt_pack_markdown(build_hunt_pack(scan))
(ROOT / "report/HUNTING_PLAYBOOK.md").write_text(md, encoding="utf-8")

mac = ROOT / "scripts/mac_triage.sh"
mac.write_text(render_script(scan, "macos"), encoding="utf-8")
mac.chmod(0o755)
print(f"{len(techs)} técnicas · playbook, layer e mac_triage.sh regenerados")
