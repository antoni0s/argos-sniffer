#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/argos_discovery.h"

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void put16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void test_nbns(void) {
    uint8_t packet[50] = {0};
    const char *name = "WORKSTATION";
    argos_discovery_nbns_t result;
    packet[12] = 0x20;
    for (size_t i = 0; i < 16U; ++i) {
        uint8_t c = i < strlen(name) ? (uint8_t)name[i] : 0x20U;
        packet[13U + i * 2U] = (uint8_t)('A' + (c >> 4));
        packet[14U + i * 2U] = (uint8_t)('A' + (c & 0x0fU));
    }
    check(argos_discovery_nbns_parse(packet, sizeof(packet), &result), "NBNS parsed");
    check(strcmp(result.name, name) == 0, "NBNS name preserved");
    packet[13] = 'Z';
    check(!argos_discovery_nbns_parse(packet, sizeof(packet), &result), "invalid NBNS rejected");
    check(!argos_discovery_nbns_parse(packet, 49U, &result), "truncated NBNS rejected");
}

static void test_arp(void) {
    uint8_t packet[28] = {0};
    const uint8_t mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t sender[4] = {192, 0, 2, 10}, target[4] = {192, 0, 2, 1};
    argos_discovery_arp_t result;
    put16(packet, 1); put16(packet + 2, 0x0800); packet[4] = 6; packet[5] = 4;
    put16(packet + 6, 2); memcpy(packet + 8, mac, 6); memcpy(packet + 14, sender, 4);
    memcpy(packet + 24, target, 4);
    check(argos_discovery_arp_parse(packet, sizeof(packet), &result), "ARP parsed");
    check(result.operation == 2U && memcmp(result.sender_mac, mac, 6) == 0,
          "ARP identity and operation preserved");
    check(memcmp(result.sender_ip, sender, 4) == 0 && memcmp(result.target_ip, target, 4) == 0,
          "ARP addresses preserved");
    packet[8] = 1;
    check(!argos_discovery_arp_parse(packet, sizeof(packet), &result), "multicast ARP owner rejected");
    check(!argos_discovery_arp_parse(packet, 27U, &result), "truncated ARP rejected");
}

static void test_dhcp4(void) {
    uint8_t packet[280] = {0};
    argos_discovery_dhcp4_t result;
    size_t pos = 240;
    packet[236] = 0x63; packet[237] = 0x82; packet[238] = 0x53; packet[239] = 0x63;
    packet[pos++] = 12; packet[pos++] = 7; memcpy(packet + pos, "edge|01", 7); pos += 7;
    packet[pos++] = 60; packet[pos++] = 6; memcpy(packet + pos, "vendor", 6); pos += 6;
    packet[pos++] = 55; packet[pos++] = 4; packet[pos++] = 1; packet[pos++] = 3;
    packet[pos++] = 6; packet[pos++] = 15; packet[pos++] = 0xff;
    check(argos_discovery_dhcp4_parse(packet, pos, &result), "DHCPv4 parsed");
    check(strcmp(result.hostname, "edge 01") == 0, "DHCPv4 delimiter sanitized");
    check(strcmp(result.vendor, "vendor") == 0, "DHCPv4 vendor preserved");
    check(strcmp(result.parameter_request_list, "1,3,6,15") == 0, "DHCPv4 PRL preserved");
    check(!argos_discovery_dhcp4_parse(packet, 239U, &result), "truncated DHCPv4 rejected");
}

static void test_dhcp6(void) {
    uint8_t packet[128] = {1, 0, 0, 1};
    argos_discovery_dhcp6_t result;
    size_t pos = 4;
    put16(packet + pos, 1); put16(packet + pos + 2, 2); put16(packet + pos + 4, 3); pos += 6;
    put16(packet + pos, 6); put16(packet + pos + 2, 4); put16(packet + pos + 4, 23);
    put16(packet + pos + 6, 24); pos += 8;
    put16(packet + pos, 16); put16(packet + pos + 2, 13);
    packet[pos + 8] = 0; packet[pos + 9] = 7; memcpy(packet + pos + 10, "acme|os", 7); pos += 17;
    put16(packet + pos, 39); put16(packet + pos + 2, 14); packet[pos + 4] = 0;
    packet[pos + 5] = 4; memcpy(packet + pos + 6, "host", 4);
    packet[pos + 10] = 7; memcpy(packet + pos + 11, "example", 7); packet[pos + 18] = 0; pos += 18;
    check(argos_discovery_dhcp6_parse(packet, pos, &result), "DHCPv6 parsed");
    check(strcmp(result.message_type, "SOLICIT") == 0 && strcmp(result.duid_type, "LL") == 0,
          "DHCPv6 message and DUID preserved");
    check(strcmp(result.option_request, "23,24") == 0, "DHCPv6 ORO preserved");
    check(strcmp(result.vendor, "acme os") == 0, "DHCPv6 vendor sanitized");
    check(strcmp(result.fqdn, "host.example") == 0, "DHCPv6 FQDN preserved");
    packet[0] = 12;
    check(!argos_discovery_dhcp6_parse(packet, pos, &result), "DHCPv6 relay rejected");
}

static void test_ndp_and_ra(void) {
    uint8_t na[32] = {136, 0, 0, 0, 0xe0};
    uint8_t frame_mac[6] = {0x02, 0, 0, 0, 0, 1};
    uint8_t option_mac[6] = {0x02, 0, 0, 0, 0, 2};
    argos_discovery_ndp_t ndp;
    argos_discovery_ra_t ra;
    na[8] = 0x20; na[9] = 0x01; na[23] = 1;
    na[24] = 2; na[25] = 1; memcpy(na + 26, option_mac, 6);
    check(argos_discovery_ndp_parse(na, sizeof(na), frame_mac, &ndp), "NDP NA parsed");
    check(strcmp(ndp.kind, "NA") == 0 && strcmp(ndp.flags, "RSO") == 0,
          "NDP kind and flags preserved");
    check(ndp.is_advertisement && ndp.has_target && memcmp(ndp.identity_mac, option_mac, 6) == 0,
          "NDP advertised identity preserved");
    check(!argos_discovery_ndp_parse(na, 23U, frame_mac, &ndp), "truncated NDP rejected");

    uint8_t advert[56] = {134, 0, 0, 0, 64, 0xc0, 0x07, 0x08};
    advert[16] = 3; advert[17] = 4; advert[18] = 64; advert[32] = 0x20; advert[33] = 0x01;
    advert[48] = 5; advert[49] = 1; advert[52] = 0; advert[53] = 0; advert[54] = 0x05; advert[55] = 0xdc;
    check(argos_discovery_ra_parse(advert, sizeof(advert), &ra), "RA parsed");
    check(ra.hop_limit == 64U && strcmp(ra.flags, "MO") == 0 && ra.lifetime == 1800U,
          "RA header preserved");
    check(ra.has_prefix && ra.prefix_length == 64U && ra.prefix[0] == 0x20 && ra.prefix[1] == 0x01,
          "RA prefix preserved");
    check(ra.mtu == 1500U, "RA MTU preserved");
}

static void test_dns_and_mdns(void) {
    uint8_t packet[64] = {0};
    argos_discovery_mdns_t result;
    uint16_t qtype = 0;
    size_t pos = 12;
    packet[5] = 1;
    packet[pos++] = 4; memcpy(packet + pos, "_IPP", 4); pos += 4;
    packet[pos++] = 4; memcpy(packet + pos, "_TCP", 4); pos += 4;
    packet[pos++] = 5; memcpy(packet + pos, "LOCAL", 5); pos += 5;
    packet[pos++] = 0; put16(packet + pos, 12); put16(packet + pos + 2, 1); pos += 4;
    check(argos_discovery_mdns_parse(packet, pos, &result), "mDNS parsed");
    check(strcmp(result.question, "_ipp._tcp.local") == 0, "DNS name normalized");
    check(argos_discovery_dns_qtype(packet, (int)pos, 12, &qtype) && qtype == 12U,
          "DNS QTYPE preserved");
    packet[12] = 0xc0; packet[13] = 12;
    check(argos_discovery_dns_name(packet, (int)pos, 12, result.question,
                                   (int)sizeof(result.question)) == 0,
          "DNS pointer loop bounded");
}

static void test_bounded_malformed_inputs(void) {
    uint8_t bytes[320];
    uint32_t state = 0x6172676fU;
    uint8_t mac[6] = {0x02, 0, 0, 0, 0, 1};
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        state = state * 1664525U + 1013904223U;
        bytes[i] = (uint8_t)(state >> 24);
    }
    for (size_t len = 0; len <= sizeof(bytes); ++len) {
        argos_discovery_nbns_t nbns;
        argos_discovery_arp_t arp;
        argos_discovery_dhcp4_t dhcp4;
        argos_discovery_dhcp6_t dhcp6;
        argos_discovery_ndp_t ndp;
        argos_discovery_ra_t ra;
        argos_discovery_mdns_t mdns;
        char name[256];
        uint16_t qtype;
        (void)argos_discovery_nbns_parse(bytes, len, &nbns);
        (void)argos_discovery_arp_parse(bytes, len, &arp);
        (void)argos_discovery_dhcp4_parse(bytes, len, &dhcp4);
        (void)argos_discovery_dhcp6_parse(bytes, len, &dhcp6);
        (void)argos_discovery_ndp_parse(bytes, len, mac, &ndp);
        (void)argos_discovery_ra_parse(bytes, len, &ra);
        (void)argos_discovery_mdns_parse(bytes, len, &mdns);
        if (len > 0U)
            (void)argos_discovery_dns_name(bytes, (int)len, 0, name, (int)sizeof(name));
        if (len > 0U) (void)argos_discovery_dns_qtype(bytes, (int)len, 0, &qtype);
    }
}

int main(void) {
    check(sizeof(argos_discovery_dhcp6_t) <= 672U, "discovery result remains bounded");
    test_nbns();
    test_arp();
    test_dhcp4();
    test_dhcp6();
    test_ndp_and_ra();
    test_dns_and_mdns();
    test_bounded_malformed_inputs();
    puts("discovery engine fixtures: PASS");
    return 0;
}
