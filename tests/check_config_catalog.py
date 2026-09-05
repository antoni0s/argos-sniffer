#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
backlog = (ROOT / "V6_BACKLOG.md").read_text(encoding="utf-8")
header = (ROOT / "src/argos_config.h").read_text(encoding="utf-8")
dispatch = (ROOT / "src/argos_dispatch.h").read_text(encoding="utf-8")
main_source = (ROOT / "src/argos-sniffer.c").read_text(encoding="utf-8")

taxonomy = backlog.split("## Canonical CLI taxonomy backlog", 1)[1]
taxonomy = taxonomy.split("## Canonical vector schema backlog", 1)[0]
expected = {}
for line in taxonomy.splitlines():
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if len(cells) != 3 or cells[0] in {"Super-group", "---"}:
        continue
    if not re.fullmatch(r"[a-z-]+", cells[0]):
        continue
    expected[cells[1]] = (cells[0], [item.strip() for item in cells[2].split(",")])

group_block = header.split("#define ARGOS_GROUP_CATALOG(X)", 1)[1]
group_block = group_block.split("typedef enum", 1)[0]
groups = {
    ident: (super_name.lower(), name)
    for ident, super_name, name in re.findall(
        r'X\(([A-Z0-9_]+), ([A-Z0-9_]+), "([a-z0-9-]+)"\)', group_block
    )
}

protocol_block = header.split("#define ARGOS_PROTOCOL_CATALOG(X)", 1)[1]
protocol_block = protocol_block.split("typedef enum", 1)[0]
protocols = {
    ident: (super_name.lower(), name)
    for ident, super_name, name in re.findall(
        r'X\(([A-Z0-9_]+), ([A-Z0-9_]+), "([a-z0-9-]+)",', protocol_block
    )
}

membership_block = header.split("#define ARGOS_GROUP_MEMBERSHIP_CATALOG(X)", 1)[1]
membership_block = membership_block.split("static const argos_group_membership_t", 1)[0]
actual = {name: (super_name, []) for _, (super_name, name) in groups.items()}
for group_id, protocol_id in re.findall(
    r'X\(([A-Z0-9_]+), ([A-Z0-9_]+)\)', membership_block
):
    assert group_id in groups, f"unknown group id {group_id}"
    assert protocol_id in protocols, f"unknown protocol id {protocol_id}"
    super_name, group_name = groups[group_id]
    protocol_super, protocol_name = protocols[protocol_id]
    assert super_name == protocol_super, f"{group_name}/{protocol_name} crosses super-groups"
    actual[group_name][1].append(protocol_name)

assert actual == expected, "V6_BACKLOG taxonomy and argos_config catalog differ"
assert len(protocols) == 101
assert len(actual) == 28

# Runtime adoption gate: legacy argv flags must compile through the canonical
# owner once, then produce the fixed startup dispatch plan before capture.
required_main_markers = (
    "argos_cli_selection_init(&cli_selection)",
    "argos_cli_selection_apply_legacy(&cli_selection",
    "argos_cli_selection_apply_legacy_all(&cli_selection",
    "argos_cli_selection_finalize(&cli_selection)",
    "argos_dispatch_plan_compile(&dispatch_plan, &cli_selection)",
    "argos_dispatch_legacy_enabled(&dispatch_plan",
    "argos_dispatch_legacy_rate_limited(&dispatch_plan",
)
for marker in required_main_markers:
    assert marker in main_source, f"missing runtime config adoption marker: {marker}"
assert "opt_syn = opt_multi = opt_dhcp" not in main_source
packet_loop = main_source.split("argos_capture_open(&capture", 1)[1]
assert "cli_selection" not in packet_loop, "selection compiler leaked into packet processing"
assert "dispatch_plan" not in packet_loop, "startup dispatch plan leaked into packet processing"
assert "argos_protocol_catalog" not in packet_loop, "protocol catalog leaked into packet processing"
assert "argos_dispatch_plan_compile" in dispatch
print("Canonical config catalog matches V6_BACKLOG taxonomy: PASS")
