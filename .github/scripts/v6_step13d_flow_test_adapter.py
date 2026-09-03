from pathlib import Path

staged = Path('tests/test_flow_state.c')
canonical = Path('tests/test_app_flow.c')
if not staged.exists():
    raise SystemExit('staged flow-state fixture missing')
canonical.write_text(staged.read_text())
staged.unlink()
print('adapted canonical test_app_flow.c to flow-state module API')
