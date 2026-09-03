from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
main_path = ROOT / "src/argos-sniffer.c"
header_path = ROOT / "src/argos_telemetry.h"

if header_path.exists():
    raise SystemExit("src/argos_telemetry.h already exists")

source = main_path.read_text()

sensor_start = source.index("/* ARGOS SPAN SENSOR MVP")
sensor_end_marker = "static uint16_t sensor_observation_inner_vlan = 0;\n"
sensor_end = source.index(sensor_end_marker, sensor_start) + len(sensor_end_marker)
sensor_block = source[sensor_start:sensor_end]
source = source[:sensor_start] + source[sensor_end:]

telemetry_start_marker = "/* ============================================================================\n * SECTION: Telemetry Output Engine"
telemetry_end_marker = "/* ============================================================================\n * SECTION: Gateway/Routed Traffic Detection & Address Ownership"
telemetry_start = source.index(telemetry_start_marker)
telemetry_end = source.index(telemetry_end_marker, telemetry_start)
telemetry_block = source[telemetry_start:telemetry_end]
source = source[:telemetry_start] + source[telemetry_end:]

include_anchor = '#include "argos_config.h"\n'
if source.count(include_anchor) != 1:
    raise SystemExit("unexpected argos_config.h include count")
source = source.replace(include_anchor, include_anchor + '#include "argos_telemetry.h"\n', 1)

header = f'''#ifndef ARGOS_TELEMETRY_H
#define ARGOS_TELEMETRY_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef ARGOS_PORTABLE_TEST
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

/* Telemetry owns sink state, sensor observation context and wire emission.
 * Protocol engines remain responsible only for producing bounded fields. */

{sensor_block}

{telemetry_block}
#endif /* ARGOS_TELEMETRY_H */
'''

header_path.write_text(header)
main_path.write_text(source)
