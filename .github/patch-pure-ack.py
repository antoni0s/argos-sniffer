from pathlib import Path

p = Path('src/argos-sniffer.c')
s = p.read_text()

repls = {
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0806, 35, 0),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0806, 48, 0),',
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88cc, 34, 0),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88cc, 47, 0),',
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8100, 33, 0),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8100, 46, 0),',
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88a8, 32, 0),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88a8, 45, 0),',
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8864, 31, 0),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8864, 44, 0),',
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86dd, 30, 0),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86dd, 43, 0),',
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 30),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 43),',
'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 9, 0),':'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 22, 0),',
'BPF_JUMP(BPF_JMP | BPF_JA, 26, 0, 0),':'BPF_JUMP(BPF_JMP | BPF_JA, 39, 0, 0),',
}
for old, new in repls.items():
    if s.count(old) != 1:
        raise SystemExit(f'expected one match: {old}')
    s = s.replace(old, new, 1)

old = '''        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),
        BPF_STMT(BPF_LD  | BPF_B | BPF_IND, 27),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, TH_FIN | TH_SYN | TH_RST, 22, 0),
        BPF_STMT(BPF_LD  | BPF_H | BPF_IND, 16),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 80,   20, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8080, 19, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 443,  18, 0),
        BPF_JUMP(BPF_JMP | BPF_JA, 18, 0, 0),
'''
new = '''        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),
        BPF_STMT(BPF_LD  | BPF_B | BPF_IND, 27),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, TH_FIN | TH_SYN | TH_RST, 35, 0),
        /* Drop zero-payload ACK/window-update traffic in-kernel. IP total
         * length must exceed IP-header + TCP-header length before HTTP/TLS
         * destination-port checks are allowed to pass the packet. */
        BPF_STMT(BPF_STX, 0),
        BPF_STMT(BPF_LD  | BPF_H | BPF_ABS, 16),
        BPF_STMT(BPF_ST, 1),
        BPF_STMT(BPF_LD  | BPF_B | BPF_IND, 26),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),
        BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 2),
        BPF_STMT(BPF_MISC | BPF_TAX, 0),
        BPF_STMT(BPF_LD  | BPF_W | BPF_MEM, 0),
        BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
        BPF_STMT(BPF_MISC | BPF_TAX, 0),
        BPF_STMT(BPF_LD  | BPF_W | BPF_MEM, 1),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 24),
        BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, 0),
        BPF_STMT(BPF_LD  | BPF_H | BPF_IND, 16),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 80,   20, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8080, 19, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 443,  18, 0),
        BPF_JUMP(BPF_JMP | BPF_JA, 18, 0, 0),
'''
if s.count(old) != 1:
    raise SystemExit('TCP BPF block did not match exactly once')
s = s.replace(old, new, 1)
p.write_text(s)
