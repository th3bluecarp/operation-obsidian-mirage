import fs from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const out = path.join(root, "network/pcaps");
fs.mkdirSync(out, { recursive: true });

const ip = value => Buffer.from(value.split(".").map(Number));
const ethernet = () => Buffer.from([0x00,0x16,0x3e,0x11,0x22,0x33,0x00,0x16,0x3e,0x44,0x55,0x66,0x08,0x00]);

function packet(src, dst, sport, dport, seq, payload) {
  const body = Buffer.from(payload);
  const ipv4 = Buffer.alloc(20);
  ipv4[0] = 0x45;
  ipv4.writeUInt16BE(40 + body.length, 2);
  ipv4.writeUInt16BE(seq & 0xffff, 4);
  ipv4[8] = 64;
  ipv4[9] = 6;
  ip(src).copy(ipv4, 12); ip(dst).copy(ipv4, 16);
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(sport, 0); tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4); tcp.writeUInt32BE(1, 8);
  tcp[12] = 0x50; tcp[13] = 0x18; tcp.writeUInt16BE(64240, 14);
  return Buffer.concat([ethernet(), ipv4, tcp, body]);
}

function writePcap(name, startIso, src, dst, sport, dport, label, count=240) {
  const global = Buffer.alloc(24);
  global.writeUInt32LE(0xa1b2c3d4,0); global.writeUInt16LE(2,4); global.writeUInt16LE(4,6);
  global.writeUInt32LE(0,8); global.writeUInt32LE(0,12); global.writeUInt32LE(65535,16); global.writeUInt32LE(1,20);
  const chunks=[global]; const start=Date.parse(startIso);
  for(let i=0;i<count;i++){
    const payload=i===0?label:`TLS application data record ${String(i).padStart(4,"0")}`;
    const frame=packet(src,dst,sport,dport,1000+i*128,payload);
    const header=Buffer.alloc(16); const ms=start+i*37;
    header.writeUInt32LE(Math.floor(ms/1000),0); header.writeUInt32LE((ms%1000)*1000,4);
    header.writeUInt32LE(frame.length,8); header.writeUInt32LE(frame.length,12);
    chunks.push(header,frame);
  }
  fs.writeFileSync(path.join(out,name),Buffer.concat(chunks));
}

writePcap("phish_session_capture.pcap","2026-02-13T08:14:00Z","10.20.4.23","185.225.17.44",51822,443,"TLS ClientHello SNI=login-review-support.com");
writePcap("jump_exfil_tls.pcap","2026-02-13T11:42:00Z","10.50.9.10","103.166.185.200",49211,443,"TLS ClientHello SNI=cdn-systempatch.net",900);
writePcap("ransomware_smb_burst.pcap","2026-02-13T12:03:00Z","10.20.4.23","10.20.1.40",51103,445,"SMB3 encrypted write burst",640);
writePcap("decoy_vpn_login.pcap","2026-02-13T07:55:00Z","45.144.31.9","10.20.1.40",44221,443,"TLS ClientHello SNI=vpn.example.internal",80);
