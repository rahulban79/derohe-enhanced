import Metal
import Foundation
setbuf(stdout, nil)

// GPU stage-3a: the 3 conditional loop hashes (fnv1a64, xxhash64, siphash-2-4) in MSL,
// validated byte-exact vs cmd/_hashref (Go, real libs). Each thread handles one test length.

let msl = """
#include <metal_stdlib>
using namespace metal;
inline ulong rotl64(ulong x, uint r){ return (x << r) | (x >> (64u - r)); }
inline ulong u64le(thread const uchar* b){ ulong r=0; for(uint i=0;i<8;i++) r|=ulong(b[i])<<(8*i); return r; }
inline uint  u32le(thread const uchar* b){ uint r=0; for(uint i=0;i<4;i++) r|=uint(b[i])<<(8*i); return r; }

constant ulong P1=11400714785074694791UL, P2=14029467366897019727UL, P3=1609587929392839161UL, P4=9650029242287828579UL, P5=2870177450012600261UL;
inline ulong xround(ulong acc, ulong in){ acc += in*P2; acc = rotl64(acc,31); acc *= P1; return acc; }
inline ulong mergeR(ulong acc, ulong val){ val = xround(0UL, val); acc ^= val; acc = acc*P1 + P4; return acc; }

static ulong fnv1a(thread const uchar* d, uint n){
    ulong h = 14695981039346656037UL;
    for(uint i=0;i<n;i++){ h = (h ^ ulong(d[i])) * 1099511628211UL; }
    return h;
}
static ulong xxh64(thread const uchar* b, uint n){
    ulong h; uint i=0;
    if(n>=32){
        ulong v1=P1+P2, v2=P2, v3=0UL, v4=0UL-P1;
        uint end=n;
        while(i+32<=end){ v1=xround(v1,u64le(b+i)); v2=xround(v2,u64le(b+i+8)); v3=xround(v3,u64le(b+i+16)); v4=xround(v4,u64le(b+i+24)); i+=32; }
        h = rotl64(v1,1)+rotl64(v2,7)+rotl64(v3,12)+rotl64(v4,18);
        h = mergeR(h,v1); h = mergeR(h,v2); h = mergeR(h,v3); h = mergeR(h,v4);
    } else { h = P5; }
    h += ulong(n);
    uint end = n;
    for(; i+8<=end; i+=8){ ulong k1=xround(0UL,u64le(b+i)); h ^= k1; h = rotl64(h,27)*P1 + P4; }
    if(i+4<=end){ h ^= ulong(u32le(b+i))*P1; h = rotl64(h,23)*P2 + P3; i+=4; }
    for(; i<end; i++){ h ^= ulong(b[i])*P5; h = rotl64(h,11)*P1; }
    h ^= h>>33; h *= P2; h ^= h>>29; h *= P3; h ^= h>>32;
    return h;
}
static ulong siphash(ulong k0, ulong k1, thread const uchar* p, uint n){
    ulong v0=k0^0x736f6d6570736575UL, v1=k1^0x646f72616e646f6dUL, v2=k0^0x6c7967656e657261UL, v3=k1^0x7465646279746573UL;
    ulong t = ulong(n) << 56;
    uint i=0;
    while(i+8<=n){
        ulong m=u64le(p+i); v3^=m;
        for(uint r=0;r<2;r++){ v0+=v1; v1=rotl64(v1,13); v1^=v0; v0=rotl64(v0,32); v2+=v3; v3=rotl64(v3,16); v3^=v2; v0+=v3; v3=rotl64(v3,21); v3^=v0; v2+=v1; v1=rotl64(v1,17); v1^=v2; v2=rotl64(v2,32); }
        v0^=m; i+=8;
    }
    uint rem=n-i;
    if(rem>=7) t|=ulong(p[i+6])<<48;
    if(rem>=6) t|=ulong(p[i+5])<<40;
    if(rem>=5) t|=ulong(p[i+4])<<32;
    if(rem>=4) t|=ulong(p[i+3])<<24;
    if(rem>=3) t|=ulong(p[i+2])<<16;
    if(rem>=2) t|=ulong(p[i+1])<<8;
    if(rem>=1) t|=ulong(p[i+0]);
    v3^=t;
    for(uint r=0;r<2;r++){ v0+=v1; v1=rotl64(v1,13); v1^=v0; v0=rotl64(v0,32); v2+=v3; v3=rotl64(v3,16); v3^=v2; v0+=v3; v3=rotl64(v3,21); v3^=v0; v2+=v1; v1=rotl64(v1,17); v1^=v2; v2=rotl64(v2,32); }
    v0^=t; v2^=0xff;
    for(uint r=0;r<4;r++){ v0+=v1; v1=rotl64(v1,13); v1^=v0; v0=rotl64(v0,32); v2+=v3; v3=rotl64(v3,16); v3^=v2; v0+=v3; v3=rotl64(v3,21); v3^=v0; v2+=v1; v1=rotl64(v1,17); v1^=v2; v2=rotl64(v2,32); }
    return v0^v1^v2^v3;
}

kernel void hashes(device const uint* lens [[buffer(0)]], constant ulong& k0 [[buffer(1)]], constant ulong& k1 [[buffer(2)]], device ulong* out [[buffer(3)]], uint gid [[thread_position_in_grid]]){
    uint n = lens[gid];
    uchar d[256];
    for(uint i=0;i<n;i++) d[i]=uchar((i*131 + n*17) & 0xff);   // == testdata() in cmd/_hashref
    out[gid*3+0]=fnv1a(d,n);
    out[gid*3+1]=xxh64(d,n);
    out[gid*3+2]=siphash(k0,k1,d,n);
}
"""

guard let dev = MTLCreateSystemDefaultDevice() else { exit(1) }
let q = dev.makeCommandQueue()!
let lib = try dev.makeLibrary(source: msl, options: nil)
let pso = try dev.makeComputePipelineState(function: lib.makeFunction(name:"hashes")!)

let lens: [UInt32] = [0,1,2,3,4,7,8,15,16,31,32,33,64,100,200,255]
let k0: UInt64 = 0x0123456789abcdef, k1: UInt64 = 0xfedcba9876543210
// Go reference (from cmd/_hashref): fnv, xxh, sip per length
let ref: [[UInt64]] = [
 [0xcbf29ce484222325,0xef46db3751d8e999,0xb7e67c99394ba858],
 [0xaf63cc4c8601d15c,0xad10cd9780ac4ff7,0x5afcccb8f93514de],
 [0x07cbef07b493b8c0,0xe874af30a1f96894,0xf8ee5169b73caa12],
 [0x58e2121823c00e7f,0x1348575e78cde972,0xbc8175b6600ce8fb],
 [0x54856c702885a9fd,0xe715877f642bcff2,0xb7dad0eaa7e7f89b],
 [0x135ed7b01e67b70b,0xfaac882f517a7b37,0x4b35a97f302b8bfb],
 [0x4614c76714188ba5,0x4872edda4a135c2c,0xc45f68a533d9d471],
 [0xea6e35dcbae36a4b,0x25ed5ff19901c727,0xc90003a78ff92888],
 [0xdccc146face09825,0xad9ebdcd6475ca1c,0x0feab8beae9e36d5],
 [0xb401dacc46781d2b,0xb31e09433962d424,0x05f5e54624339581],
 [0x1db3f6d7b931cc25,0x94144c0bd7c5680e,0xca7970c3913b3350],
 [0xce0f1ef3e064cc1c,0x6d2d15dcb8cdb5b4,0xf4e7084d5d0b7f1a],
 [0xe8f233eb22ea6ea5,0xd5b20ddbbd46fac0,0xe9c39108bd4db866],
 [0xc210f073c6c3667d,0x743eea27b717fd57,0x4b94237a4032436f],
 [0x5dc0236deaf5b4a5,0x4631f9eae26cbefb,0x8675eece899d2da4],
 [0xefd499228190f5ab,0x546cd3802107591e,0x47886e95e5b13065]]

let n = lens.count
let lbuf = dev.makeBuffer(bytes: lens, length: n*4, options: .storageModeShared)!
let obuf = dev.makeBuffer(length: n*3*8, options: .storageModeShared)!
var kk0=k0, kk1=k1
let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
e.setComputePipelineState(pso); e.setBuffer(lbuf,offset:0,index:0); e.setBytes(&kk0,length:8,index:1); e.setBytes(&kk1,length:8,index:2); e.setBuffer(obuf,offset:0,index:3)
e.dispatchThreads(MTLSize(width:n,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(n,64),height:1,depth:1))
e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
let o=obuf.contents().bindMemory(to:UInt64.self,capacity:n*3)
print("GPU 3-hash validation (fnv1a / xxhash64 / siphash) vs Go reference:")
print("len    fnv1a            xxhash64         siphash24        match")
var all=true
for i in 0..<n {
    let f=o[i*3], x=o[i*3+1], s=o[i*3+2]
    let ok = (f==ref[i][0] && x==ref[i][1] && s==ref[i][2]); if !ok { all=false }
    print(String(format:"%-5d  %016llx %016llx %016llx %@", lens[i], f, x, s, ok ? "MATCH":"MISMATCH"))
}
print("\n=== GPU STAGE-3a RESULT: \(all ? "ALL MATCH (fnv1a+xxhash+siphash bit-exact on GPU)":"MISMATCH") ===")
exit(all ? 0 : 1)
