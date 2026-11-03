import Metal
import Foundation
setbuf(stdout, nil)

// GPU Milestone 1 — building block #1: bit-exact SHA256 on the M1 GPU (Metal, runtime MSL).
// AstroBWTv3's first op is sha256.Sum256(input) (pow.go:52). This kernel computes SHA256 for
// a batch of inputs on the GPU; we validate the digests against known-answer values (shasum -a 256).
// Bit-exact here => the GPU-CPU consensus approach is sound; remaining stages (Salsa20, RC4,
// 256-op loop, SAIS) follow the same validate-against-CPU discipline before any share is trusted.

let msl = """
#include <metal_stdlib>
using namespace metal;

constant uint K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

inline uint rotr(uint x, uint n){ return (x >> n) | (x << (32u - n)); }

// SHA256 of a SHORT message (<= 55 bytes -> single 512-bit block, one length word).
// AstroBWTv3 hashes the 48-byte miniblock and small test vectors, all single-block.
kernel void sha256_1blk(device const uchar* msgs [[buffer(0)]],
                        constant uint& msglen [[buffer(1)]],
                        constant uint& stride [[buffer(2)]],
                        device uchar* outs [[buffer(3)]],
                        uint gid [[thread_position_in_grid]]) {
    device const uchar* m = msgs + (ulong)gid * stride;
    uchar blk[64];
    for (uint i=0;i<64;i++) blk[i]=0;
    for (uint i=0;i<msglen;i++) blk[i]=m[i];
    blk[msglen]=0x80;
    ulong bits = (ulong)msglen * 8;
    blk[56]=uchar(bits>>56); blk[57]=uchar(bits>>48); blk[58]=uchar(bits>>40); blk[59]=uchar(bits>>32);
    blk[60]=uchar(bits>>24); blk[61]=uchar(bits>>16); blk[62]=uchar(bits>>8); blk[63]=uchar(bits);
    uint w[64];
    for (uint i=0;i<16;i++) w[i]=(uint(blk[i*4])<<24)|(uint(blk[i*4+1])<<16)|(uint(blk[i*4+2])<<8)|uint(blk[i*4+3]);
    for (uint i=16;i<64;i++){
        uint s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
        uint s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
    for (uint i=0;i<64;i++){
        uint S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint ch=(e&f)^((~e)&g);
        uint t1=h+S1+ch+K[i]+w[i];
        uint S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint maj=(a&b)^(a&c)^(b&c);
        uint t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    uint H[8]={0x6a09e667+a,0xbb67ae85+b,0x3c6ef372+c,0xa54ff53a+d,0x510e527f+e,0x9b05688c+f,0x1f83d9ab+g,0x5be0cd19+h};
    device uchar* o = outs + (ulong)gid*32;
    for (uint i=0;i<8;i++){ o[i*4]=uchar(H[i]>>24); o[i*4+1]=uchar(H[i]>>16); o[i*4+2]=uchar(H[i]>>8); o[i*4+3]=uchar(H[i]); }
}
"""

guard let dev = MTLCreateSystemDefaultDevice() else { print("no device"); exit(1) }
let q = dev.makeCommandQueue()!
let lib = try dev.makeLibrary(source: msl, options: nil)
let pso = try dev.makeComputePipelineState(function: lib.makeFunction(name:"sha256_1blk")!)

// KA inputs (same as pow_test.go vectors + a 48-byte all-zero miniblock-like input)
let inputs: [[UInt8]] = [
    Array("a".utf8), Array("ab".utf8), Array("abc".utf8), Array("abcd".utf8),
    Array("abcde".utf8), Array("hello".utf8), Array(repeating: 0, count: 48)
]
// all inputs must share a fixed length slot? No — pad to max stride, pass per-run msglen.
// known-answer references (shasum -a 256)
let refs: [String: String] = [
    "a":"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "ab":"fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603",
    "abc":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "abcd":"88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589",
    "abcde":"36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c",
    "hello":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "48x00":"17b0761f87b081d5cf10757ccc89f12be355c70e2e29df288b65b30710dcbcd1"]
print("GPU SHA256 (Milestone-1 building block) vs known-answer (shasum -a 256):")
print("input          gpu_sha256                                                        match")
var allMatch = true
for inp in inputs {
    let stride = max(inp.count, 1)
    let mbuf = dev.makeBuffer(bytes: inp.isEmpty ? [0] : inp, length: stride, options: .storageModeShared)!
    let obuf = dev.makeBuffer(length: 32, options: .storageModeShared)!
    var ml = UInt32(inp.count); var st = UInt32(stride)
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(mbuf,offset:0,index:0); e.setBytes(&ml,length:4,index:1)
    e.setBytes(&st,length:4,index:2); e.setBuffer(obuf,offset:0,index:3)
    e.dispatchThreads(MTLSize(width:1,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:1,height:1,depth:1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    let p=obuf.contents().bindMemory(to:UInt8.self,capacity:32)
    var hex=""; for i in 0..<32 { hex += String(format:"%02x", p[i]) }
    // reference via CommonCrypto not imported; print for external shasum compare
    let label = inp.allSatisfy{ $0>=32 } ? String(bytes: inp, encoding: .utf8)! : "48x00"
    let ref = refs[label] ?? "?"
    let ok = (hex == ref)
    if !ok { allMatch = false }
    let pad = String(repeating: " ", count: max(0, 14 - label.count))
    print("\(label)\(pad) \(hex)  \(ok ? "MATCH" : "MISMATCH ref="+ref)")
}
print("\n=== GPU SHA256 MILESTONE-1 RESULT: \(allMatch ? "ALL MATCH (bit-exact vs CPU)" : "MISMATCH — NOT bit-exact") ===")
exit(allMatch ? 0 : 1)
