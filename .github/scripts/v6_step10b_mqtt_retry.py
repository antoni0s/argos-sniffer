from pathlib import Path

p=Path('.github/scripts/v6_step10b_mqtt_patch.py')
s=p.read_text()
old1='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 1, 40)), "TCP/44818 destination passes");\\n'''
new1='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 0x18, 24)), "EtherNet/IP TCP/44818 passes");\\n'''
old1r='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 1, 40)), "TCP/44818 destination passes");\\n    expect(pass(&p, pkt, tcp4(pkt, 50000, 1883, 1, 40)), "MQTT TCP/1883 destination passes");\\n'''
new1r='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 0x18, 24)), "EtherNet/IP TCP/44818 passes");\\n    expect(pass(&p, pkt, tcp4(pkt, 50000, 1883, 0x18, 24)), "MQTT TCP/1883 destination passes");\\n'''
old2='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 1, 40)), "TCP/8443 payload passes");\\n'''
new2='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 0x18, 20)), "alternate HTTPS port passes");\\n'''
old2r='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 1, 40)), "TCP/8443 payload passes");\\n    expect(pass(&p, pkt, tcp4(pkt, 50000, 8883, 1, 40)), "MQTTS TCP/8883 payload passes");\\n'''
new2r='''    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 0x18, 20)), "alternate HTTPS port passes");\\n    expect(pass(&p, pkt, tcp4(pkt, 50000, 8883, 0x18, 20)), "MQTTS TCP/8883 payload passes");\\n'''
for old,new,label in ((old1,new1,'44818 anchor'),(old1r,new1r,'44818 replacement'),(old2,new2,'8443 anchor'),(old2r,new2r,'8443 replacement')):
    if s.count(old)!=1:
        raise SystemExit(f'{label}: expected one match, got {s.count(old)}')
    s=s.replace(old,new,1)
p.write_text(s)
exec(compile(s,str(p),'exec'))
