from pathlib import Path

p=Path('src/argos-sniffer.c')
s=p.read_text()
old='''                        snprintf(ident_sig, sizeof(ident_sig), "%s|%s|%s|%s",\n                                 src_ip_str, ids[ii].protocol, ids[ii].type, ids[ii].value);\n'''
new='''                        /* Keep the dedup signature bounded by the public field\n                         * contracts instead of relying on compiler inference through\n                         * an indexed result array. */\n                        snprintf(ident_sig, sizeof(ident_sig), "%.45s|%.23s|%.23s|%.191s",\n                                 src_ip_str, ids[ii].protocol, ids[ii].type, ids[ii].value);\n'''
if s.count(old)!=1:
    raise SystemExit(f'NTLM identity signature anchor count={s.count(old)}')
p.write_text(s.replace(old,new,1))
print('bounded NTLM identity integration signature')
