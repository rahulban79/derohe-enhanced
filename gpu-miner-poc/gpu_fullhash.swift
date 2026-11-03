import Metal
import Foundation
setbuf(stdout, nil)

// GPU stage-3c: the COMPLETE AstroBWTv3 hash on GPU = pre-SAIS (sha256->salsa->rc4->256-op loop)
// + suffix array (prefix-doubling, == SAIS, proven by cmd/_sacheck) + final multi-block SHA256.
// Output: 32-byte hash per input, validated against astrobwtv3.AstroBWTv3 (cmd/_fullhashvalidate).

let opsInc = try String(contentsOfFile: "loop_ops.metal.inc", encoding: .utf8)

let helpers = """
#include <metal_stdlib>
using namespace metal;
constant uint KC[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
inline uint rotr(uint x,uint n){return (x>>n)|(x<<(32u-n));}
inline ulong rotl64(ulong x,uint r){return (x<<r)|(x>>(64u-r));}
inline uchar rev8(uchar x){ x=uchar((uint(x)&0xf0u)>>4)|uchar((uint(x)&0x0fu)<<4); x=uchar((uint(x)&0xccu)>>2)|uchar((uint(x)&0x33u)<<2); x=uchar((uint(x)&0xaau)>>1)|uchar((uint(x)&0x55u)<<1); return x; }
inline uchar rotl8(uchar x,uint k){ k&=7u; uint v=uint(x); return uchar(((v<<k)|(v>>(8u-k)))&0xffu); }
inline ulong u64le(thread const uchar* b){ ulong r=0; for(uint i=0;i<8;i++) r|=ulong(b[i])<<(8*i); return r; }
inline uint  u32le(thread const uchar* b){ uint r=0; for(uint i=0;i<4;i++) r|=uint(b[i])<<(8*i); return r; }
// sha256 compression over 8 state words with a 64-byte block
static void sha256_block(thread uint* H, thread const uchar* blk){
    uint w[64]; for(uint i=0;i<16;i++) w[i]=(uint(blk[i*4])<<24)|(uint(blk[i*4+1])<<16)|(uint(blk[i*4+2])<<8)|uint(blk[i*4+3]);
    for(uint i=16;i<64;i++){uint s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);uint s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
    uint a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(uint i=0;i<64;i++){uint S1=rotr(e,6)^rotr(e,11)^rotr(e,25);uint ch=(e&f)^((~e)&g);uint t1=h+S1+ch+KC[i]+w[i];uint S0=rotr(a,2)^rotr(a,13)^rotr(a,22);uint mj=(a&b)^(a&c)^(b&c);uint t2=S0+mj;h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}
static void sha256_1blk(thread const uchar* m, uint msglen, thread uchar* out){
    uchar blk[64]; for(uint i=0;i<64;i++) blk[i]=0; for(uint i=0;i<msglen;i++) blk[i]=m[i]; blk[msglen]=0x80;
    ulong bits=(ulong)msglen*8; for(uint i=0;i<8;i++) blk[56+i]=uchar(bits>>(56-8*i));
    uint H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    sha256_block(H,blk);
    for(uint i=0;i<8;i++){out[i*4]=uchar(H[i]>>24);out[i*4+1]=uchar(H[i]>>16);out[i*4+2]=uchar(H[i]>>8);out[i*4+3]=uchar(H[i]);}
}
// multi-block sha256 over the suffix array reinterpreted as int32 LE bytes (n*4 bytes)
static void sha256_sa(device int* sa, uint n, thread uchar* out){
    uint H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    ulong totalBytes=(ulong)n*4; uchar blk[64]; uint bl=0;
    for(uint i=0;i<n;i++){ uint v=uint(sa[i]);
        for(uint b=0;b<4;b++){ blk[bl++]=uchar(v>>(8*b)); if(bl==64){ sha256_block(H,blk); bl=0; } } }
    // pad
    blk[bl++]=0x80; if(bl>56){ while(bl<64) blk[bl++]=0; sha256_block(H,blk); bl=0; }
    while(bl<56) blk[bl++]=0;
    ulong bits=totalBytes*8; for(uint i=0;i<8;i++) blk[56+i]=uchar(bits>>(56-8*i));
    sha256_block(H,blk);
    for(uint i=0;i<8;i++){out[i*4]=uchar(H[i]>>24);out[i*4+1]=uchar(H[i]>>16);out[i*4+2]=uchar(H[i]>>8);out[i*4+3]=uchar(H[i]);}
}
static void salsa_core(thread const uchar* in16, thread const uchar* key, thread uchar* out){
    const uint S0=0x61707865,S1=0x3320646e,S2=0x79622d32,S3=0x6b206574; uint j[16];
    j[0]=S0; j[1]=uint(key[0])|uint(key[1])<<8|uint(key[2])<<16|uint(key[3])<<24; j[2]=uint(key[4])|uint(key[5])<<8|uint(key[6])<<16|uint(key[7])<<24;
    j[3]=uint(key[8])|uint(key[9])<<8|uint(key[10])<<16|uint(key[11])<<24; j[4]=uint(key[12])|uint(key[13])<<8|uint(key[14])<<16|uint(key[15])<<24;
    j[5]=S1; j[6]=uint(in16[0])|uint(in16[1])<<8|uint(in16[2])<<16|uint(in16[3])<<24; j[7]=uint(in16[4])|uint(in16[5])<<8|uint(in16[6])<<16|uint(in16[7])<<24;
    j[8]=uint(in16[8])|uint(in16[9])<<8|uint(in16[10])<<16|uint(in16[11])<<24; j[9]=uint(in16[12])|uint(in16[13])<<8|uint(in16[14])<<16|uint(in16[15])<<24;
    j[10]=S2; j[11]=uint(key[16])|uint(key[17])<<8|uint(key[18])<<16|uint(key[19])<<24; j[12]=uint(key[20])|uint(key[21])<<8|uint(key[22])<<16|uint(key[23])<<24;
    j[13]=uint(key[24])|uint(key[25])<<8|uint(key[26])<<16|uint(key[27])<<24; j[14]=uint(key[28])|uint(key[29])<<8|uint(key[30])<<16|uint(key[31])<<24; j[15]=S3;
    uint x[16]; for(uint i=0;i<16;i++) x[i]=j[i];
    for(uint r=0;r<20;r+=2){ uint u;
        u=x[0]+x[12];x[4]^=(u<<7|u>>25); u=x[4]+x[0];x[8]^=(u<<9|u>>23); u=x[8]+x[4];x[12]^=(u<<13|u>>19); u=x[12]+x[8];x[0]^=(u<<18|u>>14);
        u=x[5]+x[1];x[9]^=(u<<7|u>>25); u=x[9]+x[5];x[13]^=(u<<9|u>>23); u=x[13]+x[9];x[1]^=(u<<13|u>>19); u=x[1]+x[13];x[5]^=(u<<18|u>>14);
        u=x[10]+x[6];x[14]^=(u<<7|u>>25); u=x[14]+x[10];x[2]^=(u<<9|u>>23); u=x[2]+x[14];x[6]^=(u<<13|u>>19); u=x[6]+x[2];x[10]^=(u<<18|u>>14);
        u=x[15]+x[11];x[3]^=(u<<7|u>>25); u=x[3]+x[15];x[7]^=(u<<9|u>>23); u=x[7]+x[3];x[11]^=(u<<13|u>>19); u=x[11]+x[7];x[15]^=(u<<18|u>>14);
        u=x[0]+x[3];x[1]^=(u<<7|u>>25); u=x[1]+x[0];x[2]^=(u<<9|u>>23); u=x[2]+x[1];x[3]^=(u<<13|u>>19); u=x[3]+x[2];x[0]^=(u<<18|u>>14);
        u=x[5]+x[4];x[6]^=(u<<7|u>>25); u=x[6]+x[5];x[7]^=(u<<9|u>>23); u=x[7]+x[6];x[4]^=(u<<13|u>>19); u=x[4]+x[7];x[5]^=(u<<18|u>>14);
        u=x[10]+x[9];x[11]^=(u<<7|u>>25); u=x[11]+x[10];x[8]^=(u<<9|u>>23); u=x[8]+x[11];x[9]^=(u<<13|u>>19); u=x[9]+x[8];x[10]^=(u<<18|u>>14);
        u=x[15]+x[14];x[12]^=(u<<7|u>>25); u=x[12]+x[15];x[13]^=(u<<9|u>>23); u=x[13]+x[12];x[14]^=(u<<13|u>>19); u=x[14]+x[13];x[15]^=(u<<18|u>>14);
    }
    for(uint i=0;i<16;i++){uint v=x[i]+j[i];out[i*4]=uchar(v);out[i*4+1]=uchar(v>>8);out[i*4+2]=uchar(v>>16);out[i*4+3]=uchar(v>>24);}
}
constant ulong P1=11400714785074694791UL,P2v=14029467366897019727UL,P3=1609587929392839161UL,P4=9650029242287828579UL,P5=2870177450012600261UL;
inline ulong xr(ulong a,ulong in){a+=in*P2v;a=rotl64(a,31);a*=P1;return a;} inline ulong mr(ulong a,ulong v){v=xr(0UL,v);a^=v;a=a*P1+P4;return a;}
static ulong fnv1a(thread const uchar* d,uint n){ulong h=14695981039346656037UL;for(uint i=0;i<n;i++)h=(h^ulong(d[i]))*1099511628211UL;return h;}
static ulong xxh64(thread const uchar* b,uint n){ulong h;uint i=0; if(n>=32){ulong v1=P1+P2v,v2=P2v,v3=0UL,v4=0UL-P1;while(i+32<=n){v1=xr(v1,u64le(b+i));v2=xr(v2,u64le(b+i+8));v3=xr(v3,u64le(b+i+16));v4=xr(v4,u64le(b+i+24));i+=32;}h=rotl64(v1,1)+rotl64(v2,7)+rotl64(v3,12)+rotl64(v4,18);h=mr(h,v1);h=mr(h,v2);h=mr(h,v3);h=mr(h,v4);}else{h=P5;} h+=ulong(n); for(;i+8<=n;i+=8){ulong k1=xr(0UL,u64le(b+i));h^=k1;h=rotl64(h,27)*P1+P4;} if(i+4<=n){h^=ulong(u32le(b+i))*P1;h=rotl64(h,23)*P2v+P3;i+=4;} for(;i<n;i++){h^=ulong(b[i])*P5;h=rotl64(h,11)*P1;} h^=h>>33;h*=P2v;h^=h>>29;h*=P3;h^=h>>32; return h;}
static ulong siph(ulong k0,ulong k1,thread const uchar* p,uint n){ulong v0=k0^0x736f6d6570736575UL,v1=k1^0x646f72616e646f6dUL,v2=k0^0x6c7967656e657261UL,v3=k1^0x7465646279746573UL;ulong t=ulong(n)<<56;uint i=0;while(i+8<=n){ulong m=u64le(p+i);v3^=m;for(uint r=0;r<2;r++){v0+=v1;v1=rotl64(v1,13);v1^=v0;v0=rotl64(v0,32);v2+=v3;v3=rotl64(v3,16);v3^=v2;v0+=v3;v3=rotl64(v3,21);v3^=v0;v2+=v1;v1=rotl64(v1,17);v1^=v2;v2=rotl64(v2,32);}v0^=m;i+=8;}uint rem=n-i;if(rem>=7)t|=ulong(p[i+6])<<48;if(rem>=6)t|=ulong(p[i+5])<<40;if(rem>=5)t|=ulong(p[i+4])<<32;if(rem>=4)t|=ulong(p[i+3])<<24;if(rem>=3)t|=ulong(p[i+2])<<16;if(rem>=2)t|=ulong(p[i+1])<<8;if(rem>=1)t|=ulong(p[i]);v3^=t;for(uint r=0;r<2;r++){v0+=v1;v1=rotl64(v1,13);v1^=v0;v0=rotl64(v0,32);v2+=v3;v3=rotl64(v3,16);v3^=v2;v0+=v3;v3=rotl64(v3,21);v3^=v0;v2+=v1;v1=rotl64(v1,17);v1^=v2;v2=rotl64(v2,32);}v0^=t;v2^=0xff;for(uint r=0;r<4;r++){v0+=v1;v1=rotl64(v1,13);v1^=v0;v0=rotl64(v0,32);v2+=v3;v3=rotl64(v3,16);v3^=v2;v0+=v3;v3=rotl64(v3,21);v3^=v0;v2+=v1;v1=rotl64(v1,17);v1^=v2;v2=rotl64(v2,32);}return v0^v1^v2^v3;}
struct RC4 { uchar s[256]; uchar i; uchar j; };
static void rc4_ksa(thread RC4* r, thread uchar* key){ for(uint i=0;i<256;i++) r->s[i]=uchar(i); uchar j=0; for(uint i=0;i<256;i++){ j=uchar(j + r->s[i] + key[i]); uchar t=r->s[i]; r->s[i]=r->s[j]; r->s[j]=t; } r->i=0; r->j=0; }
static void rc4_prga(thread RC4* r, thread uchar* buf, uint n){ uchar i=r->i, j=r->j; for(uint k=0;k<n;k++){ i=uchar(i+1); uchar x=r->s[i]; j=uchar(j+x); uchar y=r->s[j]; r->s[i]=y; r->s[j]=x; buf[k]=buf[k]^r->s[uchar(x+y)]; } r->i=i; r->j=j; }
// prefix-doubling suffix array (== SAIS, proven). OPTIMIZED: 2 stable counting sorts by rank
// per round (O(n)) instead of a 5-pass radix over a composite key. device scratch: sa,rank,tmp,cnt.
static void suffix_array(device uchar* text, uint n, device int* sa, device int* rank, device int* cnt, device int* tmp){
    for(uint i=0;i<n;i++){ sa[i]=int(i); rank[i]=int(uint(text[i])); }
    for(uint k=1;;k*=2){
        // Pass A: stable sort sa -> tmp by key2 = (i+k<n ? rank[i+k]+1 : 0), range [0..n]
        for(uint c=0;c<=n;c++) cnt[c]=0;
        for(uint i=0;i<n;i++){ uint idx=uint(sa[i]); int k2=(idx+k<n)?rank[idx+k]+1:0; cnt[k2]++; }
        int sum=0; for(uint c=0;c<=n;c++){ int t=cnt[c]; cnt[c]=sum; sum+=t; }
        for(uint i=0;i<n;i++){ uint idx=uint(sa[i]); int k2=(idx+k<n)?rank[idx+k]+1:0; tmp[cnt[k2]++]=int(idx); }
        // Pass B: stable sort tmp -> sa by key1 = rank[i], range [0..n-1]
        for(uint c=0;c<n;c++) cnt[c]=0;
        for(uint i=0;i<n;i++) cnt[rank[tmp[i]]]++;
        sum=0; for(uint c=0;c<n;c++){ int t=cnt[c]; cnt[c]=sum; sum+=t; }
        for(uint i=0;i<n;i++){ sa[cnt[rank[tmp[i]]]++]=tmp[i]; }
        // recompute ranks by comparing consecutive (rank[i], key2)
        tmp[sa[0]]=0;
        for(uint i=1;i<n;i++){ int a=sa[i-1], b=sa[i];
            int k2a=(uint(a)+k<n)?rank[uint(a)+k]:-1; int k2b=(uint(b)+k<n)?rank[uint(b)+k]:-1;
            tmp[b] = tmp[a] + ((rank[a]!=rank[b] || k2a!=k2b)?1:0);
        }
        for(uint i=0;i<n;i++) rank[i]=tmp[i];
        if(rank[sa[n-1]]==int(n-1) || k>n) break;
    }
}
"""

let kernel = """
kernel void full_hash(device const uchar* msgs [[buffer(0)]], constant uint& msglen [[buffer(1)]], constant uint& stride [[buffer(2)]],
                      device uchar* outs [[buffer(3)]],
                      device uchar* datas [[buffer(4)]], constant uint& datastride [[buffer(5)]],
                      device int* saB [[buffer(6)]], device int* rankB [[buffer(7)]], device int* tmpB [[buffer(8)]], device int* cntB [[buffer(9)]], constant uint& sastride [[buffer(10)]],
                      uint gid [[thread_position_in_grid]]){
    device const uchar* m = msgs + (ulong)gid*stride;
    uchar msg[64]; for(uint i=0;i<64;i++) msg[i]=0; for(uint i=0;i<msglen;i++) msg[i]=m[i];
    uchar key[32]; sha256_1blk(msg,msglen,key);
    uchar s[256]; uchar ctr[16]; for(uint i=0;i<16;i++) ctr[i]=0;
    for(uint blk=0;blk<4;blk++){ uchar b[64]; salsa_core(ctr,key,b); for(uint i=0;i<64;i++) s[blk*64+i]=b[i]; uint u=1; for(uint i=8;i<16;i++){u+=uint(ctr[i]);ctr[i]=uchar(u);u>>=8;} }
    RC4 r; rc4_ksa(&r,s); rc4_prga(&r,s,256);
    ulong lhash=fnv1a(s,256); ulong prev_lhash=lhash;
    device uchar* data = datas + (ulong)gid*datastride;
    ulong tries=0;
    while(true){ tries++;
        ulong rs=prev_lhash^lhash^tries; uint op=uint(rs&0xffUL); uint p1=uint((rs>>8)&0xffUL); uint p2=uint((rs>>16)&0xffUL);
        if(p1>p2){uint t=p1;p1=p2;p2=t;} if(p2-p1>32){p2=p1+((p2-p1)&0x1fu);}
        switch(op){
%%OPS%%
          default: break;
        }
        uchar diff=uchar(uint(s[p1])-uint(s[p2]));
        if(diff<0x10){ prev_lhash=lhash+prev_lhash; lhash=xxh64(s,p2); }
        if(diff<0x20){ prev_lhash=lhash+prev_lhash; lhash=fnv1a(s,p2); }
        if(diff<0x30){ prev_lhash=lhash+prev_lhash; lhash=siph(tries,prev_lhash,s,p2); }
        if(diff<=0x40){ rc4_prga(&r,s,256); }
        s[255]=s[255]^s[p1]^s[p2];
        ulong off=(tries-1)*256; for(uint kk=0;kk<256;kk++) data[off+kk]=s[kk];
        if(tries>276 || (s[255]>=0xf0 && tries>260)) break;
    }
    uint dlen=uint((tries-4)*256 + (((ulong(s[253])<<8)|ulong(s[254]))&0x3ffUL));
    device int* sa = saB + (ulong)gid*sastride; device int* rank = rankB + (ulong)gid*sastride;
    device int* tmp = tmpB + (ulong)gid*sastride; device int* cnt = cntB + (ulong)gid*sastride;
    suffix_array(data, dlen, sa, rank, cnt, tmp);
    uchar out[32]; sha256_sa(sa, dlen, out);
    device uchar* o = outs + (ulong)gid*32; for(uint i=0;i<32;i++) o[i]=out[i];
}
""".replacingOccurrences(of: "%%OPS%%", with: opsInc)

let msl = helpers + kernel
guard let dev = MTLCreateSystemDefaultDevice() else { exit(1) }
let q = dev.makeCommandQueue()!
let lib: MTLLibrary
do { lib = try dev.makeLibrary(source: msl, options: nil) } catch { print("MSL ERR:\n\(error)"); exit(2) }
let pso = try dev.makeComputePipelineState(function: lib.makeFunction(name:"full_hash")!)
print("full_hash kernel compiled OK.")

let inputs: [(String,[UInt8])] = [
 ("a",[UInt8]("a".utf8)),("ab",[UInt8]("ab".utf8)),("abc",[UInt8]("abc".utf8)),("abcd",[UInt8]("abcd".utf8)),
 ("abcde",[UInt8]("abcde".utf8)),("abcdef",[UInt8]("abcdef".utf8)),("abcdefg",[UInt8]("abcdefg".utf8)),
 ("abcdefgh",[UInt8]("abcdefgh".utf8)),("abcdefghi",[UInt8]("abcdefghi".utf8)),("abcdefghij",[UInt8]("abcdefghij".utf8)),
 ("48x00",[UInt8](repeating:0,count:48))]
let DSTRIDE=278*256, SASTRIDE=71200
for (idx,(label,inp)) in inputs.enumerated() {
    let stride=max(inp.count,1)
    let mbuf=dev.makeBuffer(bytes: inp.isEmpty ? [0]:inp, length:stride, options:.storageModeShared)!
    let ob=dev.makeBuffer(length:32, options:.storageModeShared)!
    let da=dev.makeBuffer(length:DSTRIDE, options:.storageModePrivate)!
    let saB=dev.makeBuffer(length:SASTRIDE*4, options:.storageModePrivate)!
    let rankB=dev.makeBuffer(length:SASTRIDE*4, options:.storageModePrivate)!
    let tmpB=dev.makeBuffer(length:SASTRIDE*4, options:.storageModePrivate)!
    let cntB=dev.makeBuffer(length:SASTRIDE*4, options:.storageModePrivate)!
    var ml=UInt32(inp.count); var st=UInt32(stride); var ds=UInt32(DSTRIDE); var ss=UInt32(SASTRIDE)
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(mbuf,offset:0,index:0); e.setBytes(&ml,length:4,index:1); e.setBytes(&st,length:4,index:2)
    e.setBuffer(ob,offset:0,index:3); e.setBuffer(da,offset:0,index:4); e.setBytes(&ds,length:4,index:5)
    e.setBuffer(saB,offset:0,index:6); e.setBuffer(rankB,offset:0,index:7); e.setBuffer(tmpB,offset:0,index:8); e.setBuffer(cntB,offset:0,index:9); e.setBytes(&ss,length:4,index:10)
    e.dispatchThreads(MTLSize(width:1,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:1,height:1,depth:1))
    e.endEncoding(); let t0=Date(); cb.commit(); cb.waitUntilCompleted(); let dt=Date().timeIntervalSince(t0)
    let ok = cb.status == .completed
    let p=ob.contents().bindMemory(to:UInt8.self,capacity:32)
    var hex=""; for i in 0..<32 { hex+=String(format:"%02x",p[i]) }
    try Data(bytes:ob.contents(),count:32).write(to: URL(fileURLWithPath:"gpu_hash_\(idx).bin"))
    print(String(format:"%-12@ %@ (%.3fs, ok=%@)", label as NSString, hex as NSString, dt, ok ? "Y":"N"))
}
print("wrote gpu_hash_*.bin — run: go run ./cmd/_fullhashvalidate")

// ---- throughput: dispatch N threads (each a full hash of the same input) ----
print("\nGPU full-hash throughput (N parallel threads, one AstroBWTv3 hash each):")
let inp2 = [UInt8]("abcdefgh".utf8)
for N in [64, 256, 1024, 4096, 8192] {
    let scratchGB = Double(N) * Double(DSTRIDE + SASTRIDE*(4+4+4+4)) / 1e9
    guard let mbuf=dev.makeBuffer(bytes:inp2,length:inp2.count,options:.storageModeShared),
          let ob=dev.makeBuffer(length:N*32,options:.storageModeShared),
          let da=dev.makeBuffer(length:DSTRIDE*N,options:.storageModePrivate),
          let saB=dev.makeBuffer(length:SASTRIDE*4*N,options:.storageModePrivate),
          let rankB=dev.makeBuffer(length:SASTRIDE*4*N,options:.storageModePrivate),
          let tmpB=dev.makeBuffer(length:SASTRIDE*4*N,options:.storageModePrivate),
          let cntB=dev.makeBuffer(length:SASTRIDE*4*N,options:.storageModePrivate) else { print(String(format:"%7d  alloc-fail %.1fGB",N,scratchGB)); continue }
    var ml=UInt32(inp2.count); var st=UInt32(inp2.count); var ds=UInt32(DSTRIDE); var ss=UInt32(SASTRIDE)
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(mbuf,offset:0,index:0); e.setBytes(&ml,length:4,index:1); e.setBytes(&st,length:4,index:2)
    e.setBuffer(ob,offset:0,index:3); e.setBuffer(da,offset:0,index:4); e.setBytes(&ds,length:4,index:5)
    e.setBuffer(saB,offset:0,index:6); e.setBuffer(rankB,offset:0,index:7); e.setBuffer(tmpB,offset:0,index:8); e.setBuffer(cntB,offset:0,index:9); e.setBytes(&ss,length:4,index:10)
    e.dispatchThreads(MTLSize(width:N,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(N,32),height:1,depth:1))
    e.endEncoding(); let t0=Date(); cb.commit(); cb.waitUntilCompleted(); let dt=Date().timeIntervalSince(t0)
    let ok = cb.status == .completed && cb.error == nil
    print(String(format:"%7d threads  %.2fs  %8.1f H/s  scratch=%.1fGB  ok=%@", N, dt, Double(N)/dt, scratchGB, ok ? "Y":"KILL"))
    if !ok { break }
}
