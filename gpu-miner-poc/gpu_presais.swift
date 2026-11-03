import Metal
import Foundation
import CryptoKit
setbuf(stdout, nil)

// GPU Milestone-1 stage 2: SHA256 -> Salsa20/20 -> RC4 == the AstroBWTv3 pre-loop (pow.go:52-63),
// producing step_3[256], on the M1 GPU. Validated byte-exact vs the Go reference (cmd/_gpuref).

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
inline uint rotl(uint x, uint n){ return (x << n) | (x >> (32u - n)); }

// SHA256 of a single-block message (<=55 bytes) -> 32-byte digest
static void sha256_1blk(thread const uchar* m, uint msglen, thread uchar* out) {
    uchar blk[64];
    for (uint i=0;i<64;i++) blk[i]=0;
    for (uint i=0;i<msglen;i++) blk[i]=m[i];
    blk[msglen]=0x80;
    ulong bits=(ulong)msglen*8;
    for (uint i=0;i<8;i++) blk[56+i]=uchar(bits>>(56-8*i));
    uint w[64];
    for (uint i=0;i<16;i++) w[i]=(uint(blk[i*4])<<24)|(uint(blk[i*4+1])<<16)|(uint(blk[i*4+2])<<8)|uint(blk[i*4+3]);
    for (uint i=16;i<64;i++){ uint s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3); uint s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
    for (uint i=0;i<64;i++){ uint S1=rotr(e,6)^rotr(e,11)^rotr(e,25); uint ch=(e&f)^((~e)&g); uint t1=h+S1+ch+K[i]+w[i];
        uint S0=rotr(a,2)^rotr(a,13)^rotr(a,22); uint mj=(a&b)^(a&c)^(b&c); uint t2=S0+mj; h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
    uint H[8]={0x6a09e667+a,0xbb67ae85+b,0x3c6ef372+c,0xa54ff53a+d,0x510e527f+e,0x9b05688c+f,0x1f83d9ab+g,0x5be0cd19+h};
    for (uint i=0;i<8;i++){ out[i*4]=uchar(H[i]>>24); out[i*4+1]=uchar(H[i]>>16); out[i*4+2]=uchar(H[i]>>8); out[i*4+3]=uchar(H[i]); }
}

// Salsa20/20 core: 16-word LE state from Sigma + key(32) + in(16); out=64 bytes (x_i += j_i, LE)
static void salsa_core(thread const uchar* in16, thread const uchar* key, thread uchar* out) {
    const uint SIG0=0x61707865, SIG1=0x3320646e, SIG2=0x79622d32, SIG3=0x6b206574;
    uint j[16];
    j[0]=SIG0;
    j[1]=uint(key[0])|uint(key[1])<<8|uint(key[2])<<16|uint(key[3])<<24;
    j[2]=uint(key[4])|uint(key[5])<<8|uint(key[6])<<16|uint(key[7])<<24;
    j[3]=uint(key[8])|uint(key[9])<<8|uint(key[10])<<16|uint(key[11])<<24;
    j[4]=uint(key[12])|uint(key[13])<<8|uint(key[14])<<16|uint(key[15])<<24;
    j[5]=SIG1;
    j[6]=uint(in16[0])|uint(in16[1])<<8|uint(in16[2])<<16|uint(in16[3])<<24;
    j[7]=uint(in16[4])|uint(in16[5])<<8|uint(in16[6])<<16|uint(in16[7])<<24;
    j[8]=uint(in16[8])|uint(in16[9])<<8|uint(in16[10])<<16|uint(in16[11])<<24;
    j[9]=uint(in16[12])|uint(in16[13])<<8|uint(in16[14])<<16|uint(in16[15])<<24;
    j[10]=SIG2;
    j[11]=uint(key[16])|uint(key[17])<<8|uint(key[18])<<16|uint(key[19])<<24;
    j[12]=uint(key[20])|uint(key[21])<<8|uint(key[22])<<16|uint(key[23])<<24;
    j[13]=uint(key[24])|uint(key[25])<<8|uint(key[26])<<16|uint(key[27])<<24;
    j[14]=uint(key[28])|uint(key[29])<<8|uint(key[30])<<16|uint(key[31])<<24;
    j[15]=SIG3;
    uint x[16]; for (uint i=0;i<16;i++) x[i]=j[i];
    for (uint r=0;r<20;r+=2){
        uint u;
        u=x[0]+x[12]; x[4]^=rotl(u,7);  u=x[4]+x[0];  x[8]^=rotl(u,9);  u=x[8]+x[4];  x[12]^=rotl(u,13); u=x[12]+x[8]; x[0]^=rotl(u,18);
        u=x[5]+x[1];  x[9]^=rotl(u,7);  u=x[9]+x[5];  x[13]^=rotl(u,9); u=x[13]+x[9]; x[1]^=rotl(u,13); u=x[1]+x[13]; x[5]^=rotl(u,18);
        u=x[10]+x[6]; x[14]^=rotl(u,7); u=x[14]+x[10];x[2]^=rotl(u,9);  u=x[2]+x[14]; x[6]^=rotl(u,13); u=x[6]+x[2];  x[10]^=rotl(u,18);
        u=x[15]+x[11];x[3]^=rotl(u,7);  u=x[3]+x[15]; x[7]^=rotl(u,9);  u=x[7]+x[3];  x[11]^=rotl(u,13);u=x[11]+x[7]; x[15]^=rotl(u,18);
        u=x[0]+x[3];  x[1]^=rotl(u,7);  u=x[1]+x[0];  x[2]^=rotl(u,9);  u=x[2]+x[1];  x[3]^=rotl(u,13); u=x[3]+x[2];  x[0]^=rotl(u,18);
        u=x[5]+x[4];  x[6]^=rotl(u,7);  u=x[6]+x[5];  x[7]^=rotl(u,9);  u=x[7]+x[6];  x[4]^=rotl(u,13); u=x[4]+x[7];  x[5]^=rotl(u,18);
        u=x[10]+x[9]; x[11]^=rotl(u,7); u=x[11]+x[10];x[8]^=rotl(u,9);  u=x[8]+x[11]; x[9]^=rotl(u,13); u=x[9]+x[8];  x[10]^=rotl(u,18);
        u=x[15]+x[14];x[12]^=rotl(u,7); u=x[12]+x[15];x[13]^=rotl(u,9); u=x[13]+x[12];x[14]^=rotl(u,13);u=x[14]+x[13];x[15]^=rotl(u,18);
    }
    for (uint i=0;i<16;i++){ uint v=x[i]+j[i]; out[i*4]=uchar(v); out[i*4+1]=uchar(v>>8); out[i*4+2]=uchar(v>>16); out[i*4+3]=uchar(v>>24); }
}

kernel void presais(device const uchar* msgs [[buffer(0)]], constant uint& msglen [[buffer(1)]],
                    constant uint& stride [[buffer(2)]], device uchar* outs [[buffer(3)]],
                    uint gid [[thread_position_in_grid]]) {
    device const uchar* m = msgs + (ulong)gid*stride;
    uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0; for (uint i=0;i<msglen;i++) msg[i]=m[i];
    uchar key[32]; sha256_1blk(msg, msglen, key);   // stage 1: sha256(input)

    // stage 2: salsa20, in=zeros -> step_3 = keystream (256 bytes = 4 blocks, counter[8]++)
    uchar step3[256];
    uchar ctr[16]; for (uint i=0;i<16;i++) ctr[i]=0;
    for (uint blk=0; blk<4; blk++){
        uchar block[64]; salsa_core(ctr, key, block);
        for (uint i=0;i<64;i++) step3[blk*64+i]=block[i];       // in=0 => out=keystream
        uint u=1; for (uint i=8;i<16;i++){ u+=uint(ctr[i]); ctr[i]=uchar(u); u>>=8; }
    }
    // stage 3: RC4 keyed by step3, XOR step3 in place
    uchar s[256]; for (uint i=0;i<256;i++) s[i]=uchar(i);
    uchar jj=0; for (uint i=0;i<256;i++){ jj=uchar(jj + s[i] + step3[i]); uchar t=s[i]; s[i]=s[jj]; s[jj]=t; }
    uchar ii=0; jj=0;
    for (uint k=0;k<256;k++){ ii=uchar(ii+1); uchar xx=s[ii]; jj=uchar(jj+xx); uchar yy=s[jj]; s[ii]=yy; s[jj]=xx; step3[k]=step3[k]^s[uchar(xx+yy)]; }

    device uchar* o = outs + (ulong)gid*256;
    for (uint i=0;i<256;i++) o[i]=step3[i];
}
"""

guard let dev = MTLCreateSystemDefaultDevice() else { print("no device"); exit(1) }
let q = dev.makeCommandQueue()!
let lib = try dev.makeLibrary(source: msl, options: nil)
let pso = try dev.makeComputePipelineState(function: lib.makeFunction(name:"presais")!)

// ground truth from cmd/_gpuref (sha256(step_3) fingerprint)
let refFP: [String:String] = [
 "a":"a6317b9362cf0cb4b7f524fc09c327eae93143a996101413445b41ab0196634d",
 "ab":"2484f89faf5d2892eec0b853f7805b0187ecffd7ed63dc3f4df9c6d04fe13dfb",
 "abc":"23bd71255551ea8d2f51ebc765e76ddcf7534e32aba36a3400272dc4f71b051c",
 "abcd":"a740ab99dc68ffd26b23acc6420b4680a2c1dff3ad2b35be241c665bb2ef80d0",
 "abcde":"02ba4410d2530e10dcc5c4e33316481d5629654b5400572ac30f5ec8f742ad5f",
 "hello":"bdba811d3ec2aa793d7115ec8f3043d44a4817221283c09ab22b50805a77ea9d",
 "48x00":"5e76c98a4a7f9054ac75bc922406f2536a87ec9f7af2a1aae48040ae6166249b"]
let inputs: [(String,[UInt8])] = [
 ("a",Array("a".utf8)),("ab",Array("ab".utf8)),("abc",Array("abc".utf8)),("abcd",Array("abcd".utf8)),
 ("abcde",Array("abcde".utf8)),("hello",Array("hello".utf8)),("48x00",Array(repeating:0,count:48))]
print("GPU pre-SAIS (sha256->salsa20->rc4) step_3 fingerprint vs Go reference:")
print("input          gpu_fp=sha256(step_3)                                             match")
var all = true
for (label,inp) in inputs {
    let stride = max(inp.count,1)
    let mbuf = dev.makeBuffer(bytes: inp.isEmpty ? [0]:inp, length: stride, options:.storageModeShared)!
    let obuf = dev.makeBuffer(length:256, options:.storageModeShared)!
    var ml=UInt32(inp.count); var st=UInt32(stride)
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(mbuf,offset:0,index:0); e.setBytes(&ml,length:4,index:1); e.setBytes(&st,length:4,index:2); e.setBuffer(obuf,offset:0,index:3)
    e.dispatchThreads(MTLSize(width:1,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:1,height:1,depth:1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    let p=obuf.contents().bindMemory(to:UInt8.self,capacity:256)
    let step3=Data(bytes:p,count:256)
    let fp=SHA256.hash(data:step3).map{String(format:"%02x",$0)}.joined()
    let ok = (fp == (refFP[label] ?? "?"))
    if !ok { all=false }
    let pad=String(repeating:" ",count:max(0,14-label.count))
    print("\(label)\(pad) \(fp)  \(ok ? "MATCH":"MISMATCH")")
}
print("\n=== GPU STAGE-2 RESULT: \(all ? "ALL MATCH (sha256+salsa20+rc4 bit-exact on GPU)":"MISMATCH") ===")
exit(all ? 0 : 1)
