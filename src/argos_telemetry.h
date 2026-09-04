#ifndef ARGOS_TELEMETRY_H
#define ARGOS_TELEMETRY_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef ARGOS_PORTABLE_TEST
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

/* Telemetry owns sink state, sensor observation context and wire emission.
 * Protocol engines remain responsible only for producing bounded fields. */

/* ARGOS SPAN SENSOR MVP ---------------------------------------------------
 * Gateway mode remains the default and keeps the legacy wire format.
 * Sensor mode adds only an observation envelope at the telemetry sink. */
#define SENSOR_NAME_MAX 64
#define SENSOR_IFACE_MAX 32
static int opt_sensor_mode = 0;
static char sensor_name[SENSOR_NAME_MAX] = {0};
static char sensor_observation_iface[SENSOR_IFACE_MAX] = {0};
static uint16_t sensor_observation_outer_vlan = 0;
static uint16_t sensor_observation_inner_vlan = 0;

/* Copy capture provenance into sink-owned bounded storage. Call only in sensor
 * mode. Preserve the legacy two-VID projection, including zero/absent ambiguity
 * and equal-tag coalescing; lossless VLAN semantics need a separate schema gate. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline void argos_telemetry_capture_context(const char *iface,
                                                    uint16_t outer, uint16_t inner,
                                                    int aux_valid, uint16_t aux_vlan) {
    if (aux_valid) {
        if (outer == 0U) outer = aux_vlan;
        else if (aux_vlan != outer) { inner = outer; outer = aux_vlan; }
    }
    snprintf(sensor_observation_iface, sizeof(sensor_observation_iface), "%s", iface);
    sensor_observation_outer_vlan = outer;
    sensor_observation_inner_vlan = inner;
}


/* ============================================================================
 * SECTION: Telemetry Output Engine
 * Handles transmission of formatted telemetry strings to any combination of:
 *   - a local Unix domain socket (-o <path>), e.g. a local collector daemon
 *     running on the same router;
 *   - a remote UDP socket (-u / -U <ip>:<port>), i.e. the
 *     "Native Remote Socket" feature -- a direct, dependency-free way to
 *     ship telemetry straight to a central server over the network without
 *     needing a local relay process;
 *   - stdout, used for local daemon pipelines and enabled by -U.
 * All configured sinks receive every record. The -U path intentionally fans out
 * to both UDP and stdout so a supervising daemon can continue parsing events;
 * -u selects the UDP-only variant.
 * ============================================================================ */
static int udp_only = 0;

#ifdef ARGOS_PORTABLE_TEST
static void emit_telemetry(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void emit_telemetry(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#else
static int ipc_sock = -1;
static struct sockaddr_un ipc_addr;
static int use_ipc = 0;

static int remote_sock = -1;
static struct sockaddr_storage remote_addr;
static socklen_t remote_addr_len = 0;
static int use_remote = 0;

/* Startup failure or stopped capture only; never closes stdout. */
static inline void argos_telemetry_close(void) {
    if (ipc_sock >= 0) close(ipc_sock);
    if (remote_sock >= 0) close(remote_sock);
    ipc_sock = remote_sock = -1;
    use_ipc = use_remote = udp_only = 0;
}

/**
 * Parses a "host:port" (or "[host]:port" for an IPv6 literal, per the usual
 * URI bracket convention needed to disambiguate the address's own colons
 * from the port separator) spec for the -U remote telemetry socket.
 * `host` may be a numeric IPv4/IPv6 address or a resolvable hostname --
 * resolution is done once at startup via getaddrinfo(), which also gives us
 * a ready-to-use sockaddr for whichever address family the host resolved
 * to. On success fills *out_addr and *out_len and returns 0; returns -1 (with a
 * message already printed to stderr) on any parse or resolution failure.
 */
static int parse_host_port(const char *spec, struct sockaddr_storage *out_addr, socklen_t *out_len) {
    char host[256]; const char *port_str;

    if (spec[0] == '[') {
        /* "[host]:port" -- bracketed form, required for IPv6 literals like
         * [2001:db8::1]:5140 since a bare IPv6 address already contains
         * colons. */
        const char *close = strchr(spec, ']');
        if (!close || close[1] != ':' || close[2] == '\0') {
            fprintf(stderr, "Error: -U expects [host]:port for a bracketed address, got '%s'\n", spec);
            return -1;
        }
        size_t hlen = (size_t)(close - (spec + 1));
        if (hlen == 0 || hlen >= sizeof(host)) {
            fprintf(stderr, "Error: -U host part too long in '%s'\n", spec);
            return -1;
        }
        memcpy(host, spec + 1, hlen); host[hlen] = '\0';
        port_str = close + 2;
    } else {
        /* Plain "host:port" -- split on the last colon so IPv4 dotted-quads
         * and hostnames (which never contain a colon) work as expected. */
        const char *colon = strrchr(spec, ':');
        if (!colon || colon == spec || colon[1] == '\0') {
            fprintf(stderr, "Error: -U expects host:port, got '%s'\n", spec);
            return -1;
        }
        size_t hlen = (size_t)(colon - spec);
        if (hlen == 0 || hlen >= sizeof(host)) {
            fprintf(stderr, "Error: -U host part missing or too long in '%s'\n", spec);
            return -1;
        }
        memcpy(host, spec, hlen); host[hlen] = '\0';
        if (strchr(host, ':')) {
            fprintf(stderr, "Error: -U IPv6 literals must use [host]:port, got '%s'\n", spec);
            return -1;
        }
        port_str = colon + 1;
    }

    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* accept whichever of IPv4/IPv6 the host resolves to */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "Error: -U could not resolve '%s': %s\n", spec, gai_strerror(rc));
        return -1;
    }
    memcpy(out_addr, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/**
 * Emits a telemetry record using a formatted string. Sends to every
 * configured sink (local IPC socket and/or remote UDP socket); if neither
 * is configured, prints to stdout instead. Both sendto() calls use
 * MSG_DONTWAIT on unconnected datagram sockets, so a slow/unreachable
 * collector (local or remote) can never stall the packet capture loop --
 * telemetry delivery here is deliberately best-effort/fire-and-forget, the
 * same trade-off the pre-existing -o local IPC path already made.
 */
static void emit_telemetry(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void emit_telemetry(const char *format, ...) {
    char event[1024];
    va_list args;
    va_start(args, format);
    int event_len = vsnprintf(event, sizeof(event), format, args);
    va_end(args);

    if (event_len < 0) return;
    if (event_len >= (int)sizeof(event)) {
        /* Preserve the legacy 1024-byte event bound. The sensor envelope is
         * added outside this buffer so enabling --sensor cannot reduce the
         * amount of parser payload that fits in a record. */
        event_len = (int)sizeof(event) - 1;
    }
    if (event_len <= 0) return;

    const char *wire = event;
    int wire_len = event_len;
    char sensor_wire[1280];
    if (opt_sensor_mode) {
        char vlan[24];
        if (sensor_observation_inner_vlan != 0U) {
            snprintf(vlan, sizeof(vlan), "%u/%u",
                     (unsigned)sensor_observation_outer_vlan,
                     (unsigned)sensor_observation_inner_vlan);
        } else {
            snprintf(vlan, sizeof(vlan), "%u", (unsigned)sensor_observation_outer_vlan);
        }
        int n = snprintf(sensor_wire, sizeof(sensor_wire), "OBS|%s|%s|%s|%.*s",
                         sensor_name,
                         sensor_observation_iface[0] ? sensor_observation_iface : "unknown",
                         vlan, event_len, event);
        if (n < 0) return;
        wire_len = n >= (int)sizeof(sensor_wire) ? (int)sizeof(sensor_wire) - 1 : n;
        wire = sensor_wire;
    }

    if (use_ipc) {
        sendto(ipc_sock, wire, (size_t)wire_len, MSG_DONTWAIT, (struct sockaddr *)&ipc_addr, sizeof(ipc_addr));
    }
    if (use_remote) {
        sendto(remote_sock, wire, (size_t)wire_len, MSG_DONTWAIT, (struct sockaddr *)&remote_addr, remote_addr_len);
    }
    /* -U is a fan-out sink: keep stdout active for the local daemon while
     * also delivering the same record to the remote UDP collector. */
    if ((use_remote && !udp_only) || (!use_remote && !use_ipc)) {
        fwrite(wire, 1U, (size_t)wire_len, stdout);
    }
}
#endif


#endif /* ARGOS_TELEMETRY_H */
