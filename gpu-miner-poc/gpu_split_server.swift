// gpu_split_server: the GPU half of dero-miner --gpu-mode=split (Round 18). Kernels k_s1tg (AstroBWTv3 stage 1:
// sha256 -> salsa20 -> rc4 -> the 256-op loop, writing the stage-1 text) and k_shaw (final SHA-256 over the suffix
// array) started as the bit-exact kernels of the r16/r17 split prototypes. The CPU does the suffix sort.
// Round 20 (same outputs, faster): k_shaw is generated fully unrolled (k_shaw_r18 kept for reference), the standard
// ops keep s[i]/s[p2] in registers, the threadgroup hashes load whole words, and stage 1 runs in 8-wide threadgroups.
// Build: cd gpu-miner-poc && xcrun swiftc -O gpu_split_server.swift -o gpu_split_server
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
// ---- LINEAR SA-IS (sais_32, validated bit-exact by gpu_sais.swift/_saisvalidate) ----
static void sa_freq(device int* text, uint n, device int* freq, uint tmax){ for(uint c=0;c<tmax;c++) freq[c]=0; for(uint i=0;i<n;i++) freq[text[i]]++; }
// OPT1 (freq-hoist): bmax/bmin are now PURE prefix-sums over an already-computed freq[] (caller fills it
// once per level per pass via sa_freq). Cuts freq recompute from 6x/level to 2x/level.
static void sa_bmax(device int* freq, device int* bucket, uint tmax){ int t=0; for(uint c=0;c<tmax;c++){ t+=freq[c]; bucket[c]=t; } }
static void sa_bmin(device int* freq, device int* bucket, uint tmax){ int t=0; for(uint c=0;c<tmax;c++){ bucket[c]=t; t+=freq[c]; } }
static int sa_placeLMS(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    sa_bmax(freq,bucket,tmax); int numLMS=0,lastB=-1,c0=0,c1=0; bool isS=false;
    for(int i=int(n)-1;i>=0;i--){ c1=c0; c0=text[i]; if(c0<c1) isS=true; else if(c0>c1&&isS){ isS=false; int b=bucket[c1]-1; bucket[c1]=b; sa[b]=i+1; lastB=b; numLMS++; } }
    if(numLMS>1) sa[lastB]=0; return numLMS; }
static void sa_subL(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    sa_bmin(freq,bucket,tmax); int k=int(n)-1,c0=text[k-1],c1=text[k]; if(c0<c1) k=-k; int cB=c1,b=bucket[cB]; sa[b]=k; b++;
    for(uint i=0;i<n;i++){ int j=sa[i]; if(j==0) continue; if(j<0){ sa[i]=-j; continue; } sa[i]=0; int kk=j-1,cc0=text[kk-1],cc1=text[kk]; if(cc0<cc1) kk=-kk; if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; } sa[b]=kk; b++; } }
static void sa_subS(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    sa_bmax(freq,bucket,tmax); int cB=0,b=bucket[cB],top=int(n);
    for(int i=int(n)-1;i>=0;i--){ int j=sa[i]; if(j==0) continue; sa[i]=0; if(j<0){ top--; sa[top]=-j; continue; } int kk=j-1,cc1=text[kk],cc0=text[kk-1]; if(cc0>cc1) kk=-kk; if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; } b--; sa[b]=kk; } }
static void sa_len(device int* text, uint n, device int* sa, int numLMS){
    int end=0,c0=0,c1=0; bool isS=false;
    for(int i=int(n)-1;i>=0;i--){ c1=c0; c0=text[i]; if(c0<c1) isS=true; else if(c0>c1&&isS){ isS=false; int j=i+1; int code=(end==0)?0:(end-j); sa[j>>1]=code; end=j+1; } } }
static int sa_id(device int* text, uint n, device int* sa, int numLMS){
    int id=0,lastLen=-1,lastPos=0;
    for(int t=int(n)-numLMS;t<int(n);t++){ int j=sa[t]; int nn=sa[j/2]; bool isNew=false;
        if(nn!=lastLen) isNew=true; else if(uint(nn)>=n) isNew=false; else { for(int i=0;i<nn;i++){ if(text[j+i]!=text[lastPos+i]){ isNew=true; break; } } }
        if(isNew){ id++; lastPos=j; lastLen=nn; } sa[j/2]=id; } return id; }
static void sa_indL(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    sa_bmin(freq,bucket,tmax); int k=int(n)-1,c0=text[k-1],c1=text[k]; if(c0<c1) k=-k; int cB=c1,b=bucket[cB]; sa[b]=k; b++;
    for(uint i=0;i<n;i++){ int j=sa[i]; if(j<=0) continue; int kk=j-1,cc1=text[kk]; if(kk>0){ int cc0=text[kk-1]; if(cc0<cc1) kk=-kk; } if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; } sa[b]=kk; b++; } }
static void sa_indS(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    sa_bmax(freq,bucket,tmax); int cB=0,b=bucket[cB];
    for(int i=int(n)-1;i>=0;i--){ int j=sa[i]; if(j>=0) continue; j=-j; sa[i]=j; int kk=j-1,cc1=text[kk]; if(kk>0){ int cc0=text[kk-1]; if(cc0<=cc1) kk=-kk; } if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; } b--; sa[b]=kk; } }
static void sa_expand(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax, int numLMS){
    sa_bmax(freq,bucket,tmax); int x=numLMS-1,saX=sa[x],c=text[saX],b=bucket[c]-1; bucket[c]=b;
    for(int i=int(n)-1;i>=0;i--){ if(i!=b){ sa[i]=0; continue; } sa[i]=saX; if(x>0){ x--; saX=sa[x]; c=text[saX]; b=bucket[c]-1; bucket[c]=b; } } }
static void sa_lmspos(device int* text, uint n, device int* dst, int numLMS){
    int j=numLMS,c0=0,c1=0; bool isS=false;
    for(int i=int(n)-1;i>=0;i--){ c1=c0; c0=text[i]; if(c0<c1) isS=true; else if(c0>c1&&isS){ isS=false; j--; dst[j]=i+1; } } }
// full flattened SA-IS: promote byte data -> TP[0..n) int32, build SA into SP[0..n). TP/SP hold >=2n int32.
static void sais_build(device uchar* data, uint n0, device int* TP, device int* SP, device int* FQ, device int* BK){
    for(uint i=0;i<n0;i++) TP[i]=int(uint(data[i]));
    uint tbase[16]; uint sbase[16]; uint flen[16]; uint ftmax[16]; int fnum[16]; int fmaxid[16]; bool frec[16]; int depth=0;
    uint curTb=0,curSb=0,curN=n0,curTM=256; uint nextTb=n0,nextSb=n0;
    while(true){ device int* text=TP+curTb; device int* sa=SP+curSb; for(uint i=0;i<curN;i++) sa[i]=0;
        sa_freq(text,curN,FQ,curTM); // OPT1: compute freq ONCE per level (down pass); placeLMS/subL/subS reuse it
        int numLMS=sa_placeLMS(text,curN,sa,FQ,BK,curTM); int maxID=0; bool rec=false;
        if(numLMS>1){ sa_subL(text,curN,sa,FQ,BK,curTM); sa_subS(text,curN,sa,FQ,BK,curTM); sa_len(text,curN,sa,numLMS); maxID=sa_id(text,curN,sa,numLMS); rec=(maxID<numLMS); }
        tbase[depth]=curTb; sbase[depth]=curSb; flen[depth]=curN; ftmax[depth]=curTM; fnum[depth]=numLMS; fmaxid[depth]=maxID; frec[depth]=rec; depth++;
        if(rec){ device int* rt=TP+nextTb; int w=0; for(uint i=0;i<=curN/2;i++){ int v=sa[i]; if(v>0){ rt[w]=v-1; w++; } }
            curTb=nextTb; curSb=nextSb; nextTb+=uint(numLMS); nextSb+=uint(numLMS); curN=uint(numLMS); curTM=uint(maxID); continue; }
        break; }
    for(int d=depth-1;d>=0;d--){ device int* text=TP+tbase[d]; device int* sa=SP+sbase[d]; uint N=flen[d]; uint TM=ftmax[d]; int numLMS=fnum[d];
        sa_freq(text,N,FQ,TM); // OPT1: recompute freq ONCE per level (up pass; FQ was clobbered by deeper recursion); expand/indL/indS reuse it
        if(numLMS>1){ if(frec[d]){ device int* childSa=SP+sbase[d+1]; device int* unmap=sa+(N-uint(numLMS)); sa_lmspos(text,N,unmap,numLMS); for(int i=0;i<numLMS;i++) sa[i]=unmap[childSa[i]]; }
            else { for(int i=0;i<numLMS;i++) sa[i]=sa[int(N)-numLMS+i]; } sa_expand(text,N,sa,FQ,BK,TM,numLMS); }
        sa_indL(text,N,sa,FQ,BK,TM); sa_indS(text,N,sa,FQ,BK,TM); }
}
"""
import CommonCrypto
// ===== r16 scratch proxy: split full_hash into k_s1 (stage-1) / k_sha (final SHA) and measure each =====
func tgOverloads(_ h: String) -> String {
    var out = ""
    for line in h.split(separator: "\n", omittingEmptySubsequences: false) {
        let l = String(line)
        // r20: the threadgroup copies of u64le/u32le/fnv1a load whole words. Every caller passes an address that is
        // 8-aligned for u64le (xxh64/siph step i by 8 or 32 from s) and 4-aligned for u32le, because each thread's s
        // starts at a multiple of 8 in threadgroup memory (ST is 520 bytes; the threadgroup base is 16-aligned).
        // Apple GPUs are little-endian, so a word load equals the byte-by-byte little-endian assembly.
        if l.hasPrefix("inline ulong u64le(") { out += "inline ulong u64le(threadgroup const uchar* b){ return *(threadgroup const ulong*)b; }\n"; continue }
        if l.hasPrefix("inline uint  u32le(") { out += "inline uint  u32le(threadgroup const uchar* b){ return *(threadgroup const uint*)b; }\n"; continue }
        // r22: the threadgroup PRGA loads S[i+1] and S[x+y] before this step's swap stores and fixes them up for the swap
        // (S'[i+1] = x when i+1 == j; S'[t] = x when t == j, y when t == i), so the next step's j does not wait on the
        // stores, and xors the keystream into buf a word at a time. Same keystream, same state (every call is n=256 on
        // an 8-aligned buf). r22 A/B: x0.94 on the LUT kernel.
        if l.hasPrefix("static void rc4_prga(") {
            out += "static void rc4_prga(threadgroup RC4* r, threadgroup uchar* buf, uint n){ threadgroup uchar* S=r->s; uint i=r->i, j=r->j; uint x=S[(i+1)&255u];"
            out += " for(uint k=0;k<n;k+=4){ uint w=0; for(uint q=0;q<4;q++){ i=(i+1)&255u; j=(j+x)&255u; uint y=S[j]; uint i1=(i+1)&255u; uint xn=S[i1]; uint tt=(x+y)&255u; uint o=S[tt];"
            out += " S[i]=uchar(y); S[j]=uchar(x); o=(tt==j)?x:((tt==i)?y:o); xn=(i1==j)?x:xn; w|=o<<(8u*q); x=xn; }"
            out += " *(threadgroup uint*)(buf+k)^=w; } r->i=uchar(i); r->j=uchar(j); }\n"
            continue
        }
        if l.hasPrefix("static ulong fnv1a(") {
            out += "static ulong fnv1a(threadgroup const uchar* d,uint n){ulong h=14695981039346656037UL;uint i=0;for(;i+8<=n;i+=8){ulong w=*(threadgroup const ulong*)(d+i);for(uint k=0;k<8;k++){h=(h^(w&0xffUL))*1099511628211UL;w>>=8;}}for(;i<n;i++)h=(h^ulong(d[i]))*1099511628211UL;return h;}\n"
            continue
        }
        if l.hasPrefix("inline ulong u64le(") || l.hasPrefix("inline uint  u32le(") || l.hasPrefix("static ulong fnv1a(") ||
           l.hasPrefix("static ulong xxh64(") || l.hasPrefix("static ulong siph(") || l.hasPrefix("static void rc4_ksa(") || l.hasPrefix("static void rc4_prga(") {
            out += l.replacingOccurrences(of: "thread ", with: "threadgroup ") + "\n"
        }
    }
    return out
}
// r20: register-resident op bodies. In the generated standard op (4 statements over s[i] and s[p2]) every statement
// loads and stores threadgroup memory, and s[p2] is reloaded after each store because the compiler cannot prove
// i != p2. Inside the loop i < p2, so s[p2] is constant: read it once (y), keep s[i] in a register (x), store once.
// Only lines of exactly that shape are rewritten (op 0 swaps s[p1]/s[p2] in its loop and op 253 hashes per byte; both
// stay verbatim); the count is checked so a regenerated loop_ops.metal.inc cannot silently fall back.
func registerOps(_ inc: String) -> (String, Int) {
    let pre = "  for(uint i=p1;i<p2;i++){ ", suf = " } break; }"
    var out = "", n = 0
    for line in inc.split(separator: "\n", omittingEmptySubsequences: false) {
        let l = String(line)
        if l.hasPrefix(pre) && l.hasSuffix(suf) {
            let st = l.dropFirst(pre.count).dropLast(suf.count).split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            let conv = st.map { $0.replacingOccurrences(of: "s[i]", with: "x").replacingOccurrences(of: "s[p2]", with: "y") }
            if st.count == 4 && st.allSatisfy({ $0.hasPrefix("s[i]=") }) && !conv.contains(where: { $0.contains("s[") || $0.contains("hash") || $0.contains("(&") }) {
                out += "  { uchar y=s[p2]; for(uint i=p1;i<p2;i++){ uchar x=s[i]; " + conv.joined(separator: "; ") + "; s[i]=x; } } break; }\n"
                n += 1
                continue
            }
        }
        out += l + "\n"
    }
    return (out, n)
}
let (opsReg, opsRegN) = registerOps(opsInc)
if opsRegN != 253 { fputs("loop_ops.metal.inc: \(opsRegN) standard ops rewritten, want 253\n", stderr); exit(2) }
// r22: table-driven stage-1 ops. A standard op applies 4 statements to every byte s[i] of [p1,p2); each statement is
// a function of x=s[i] alone, except x=x^y / x=x&y with y=s[p2] (constant inside the loop, r20). So an op is at most 3
// byte->byte maps T0,T1,T2 separated by at most 2 y-steps "x=(x&am)^xm" (xor: am=0xff,xm=y; and: am=y,xm=0; none:
// am=0xff,xm=0): x' = T2[((T1[((T0[x]&am1)^xm1)]&am2)^xm2]. k_lut builds the 256 x 3 x 256-byte tables ONCE at server
// start, on the GPU, by running the op's own generated MSL statements on every byte value, so a table entry is the
// original expression by construction (no second implementation). The stage-1 kernel then runs one short, identical
// loop for every op instead of a 256-way switch whose 8 lanes each take a different case (r22 profile: the per-lane op
// switch was ~50% of k_s1tg time; the same per-byte work with no divergence costs half). OPD[op]: bits 0-1 and 2-3 the
// two y-steps (1 xor, 2 and), 0x20000 = rc4_ksa first (ops 254/255), 0x10000 = special: op 0 (swaps s[p1]/s[p2] inside
// its loop) and op 253 (hashes per byte) keep their verbatim case. lutOps refuses any other shape (the server exits).
func lutOps(_ inc: String) -> (opd: [UInt32], build: String, special: String, n: Int) {
    let pre = "  for(uint i=p1;i<p2;i++){ ", suf = " } break; }"
    var opd = [UInt32](repeating: 0xFFFFFFFF, count: 256), build = "", special = "", n = 0
    let lines = inc.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    var k = 0
    while k < lines.count {
        let l = lines[k]
        guard l.hasPrefix("case ") && l.hasSuffix(": {") else { k += 1; continue }
        let ops = l.dropLast(2).split(separator: ":").compactMap { c -> Int? in
            let t = c.trimmingCharacters(in: .whitespaces); return t.hasPrefix("case ") ? Int(t.dropFirst(5)) : nil }
        var j = k + 1, ksa = false
        if j < lines.count && lines[j] == "  rc4_ksa(&r, s);" { ksa = true; j += 1 }
        let body = j < lines.count ? lines[j] : ""
        var segs: [[String]] = [[]], yops: [UInt32] = [], ok = false
        if body.hasPrefix(pre) && body.hasSuffix(suf) {
            let st = body.dropFirst(pre.count).dropLast(suf.count).split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            let conv = st.map { $0.replacingOccurrences(of: "s[i]", with: "x").replacingOccurrences(of: "s[p2]", with: "y") }
            ok = st.count == 4 && st.allSatisfy({ $0.hasPrefix("s[i]=") }) && !conv.contains(where: { $0.contains("s[") || $0.contains("hash") || $0.contains("(&") })
            for c in conv where ok {
                if c == "x=x^y" { yops.append(1); segs.append([]) }
                else if c == "x=x&y" { yops.append(2); segs.append([]) }
                else if c.dropFirst(2).contains("y") { ok = false }
                else { segs[segs.count - 1].append(c) }
            }
            ok = ok && yops.count <= 2
        }
        if ok {
            while segs.count < 3 { segs.append([]) }
            var d: UInt32 = ksa ? 0x20000 : 0
            for (q, y) in yops.enumerated() { d |= y << (2 * UInt32(q)) }
            for o in ops { opd[o] = d }
            build += l + " " + (0..<3).map { "if(seg==\($0)u){ " + segs[$0].map { $0 + "; " }.joined() + "}" }.joined(separator: " else ") + " break; }\n"
            n += 1
            k = j + 1
            continue
        }
        // special: the case verbatim (label, optional rc4_ksa, body) up to the next label
        var e = k + 1
        while e < lines.count && !(lines[e].hasPrefix("case ") && lines[e].hasSuffix(": {")) { e += 1 }
        special += lines[k..<e].joined(separator: "\n") + "\n"
        for o in ops { opd[o] = 0x10000 }
        k = e
    }
    return (opd, build, special, n)
}
let (lutOPD, lutBuild, lutSpecial, lutN) = lutOps(opsInc)
if lutN != 253 || lutOPD.contains(0xFFFFFFFF) || lutOPD.enumerated().filter({ $0.element == 0x10000 }).map({ $0.offset }) != [0, 253] {
    fputs("loop_ops.metal.inc: \(lutN) table-driven ops, want 253 (special ops must be exactly 0 and 253)\n", stderr); exit(2)
}
let lutMSL = "constant uint OPD[256] = {" + lutOPD.map { String(format: "0x%x", $0) }.joined(separator: ",") + "};\n" + """
kernel void k_lut(device uchar* LUT [[buffer(0)]], uint gid [[thread_position_in_grid]]){
    uint op=gid/768u, seg=(gid/256u)%3u; uchar x=uchar(gid&255u);
    switch(op){
\(lutBuild)      default: break;
    }
    LUT[gid]=x;
}
"""
// the k_s1tg op step: the special ops' verbatim cases, else rc4_ksa (254/255) and the table loop. The loop works on
// aligned 32-bit words of s (s is 8-aligned in threadgroup memory, ST): 4 independent table chains per word, and the
// bytes outside [p1,p2) are written back unchanged through the mask m. The word holding s[p2] is rewritten with its
// own bytes, which is safe: only this thread touches its s, and y=s[p2] was read before the loop (r22 A/B: x0.93 vs
// the byte loop).
let lutStep = """
            { uint dd=OPD[op];
              if(dd & 0x10000u){ switch(op){
\(lutSpecial)              default: break; } }
              else { if(dd & 0x20000u) rc4_ksa(&r, s); uchar y=s[p2];
                uchar am1=(dd&2u)?y:uchar(0xff), xm1=(dd&1u)?y:uchar(0), am2=(dd&8u)?y:uchar(0xff), xm2=(dd&4u)?y:uchar(0);
                device const uchar* T0=LUT+op*768u;
                for(uint w=p1&~3u;w<p2;w+=4){ uint v=*(threadgroup const uint*)(s+w); uint rr=0;
                  for(uint q=0;q<4;q++){ uchar x=T0[(v>>(8u*q))&0xffu]; x=(x&am1)^xm1; x=T0[256u+x]; x=(x&am2)^xm2; rr|=uint(T0[512u+x])<<(8u*q); }
                  uint lo=(w<p1)?(p1-w):0u; uint hi=min(4u,p2-w); uint m=(hi>=4u?0xffffffffu:((1u<<(8u*hi))-1u)) & ~((1u<<(8u*lo))-1u);
                  *(threadgroup uint*)(s+w)=(v&~m)|(rr&m); } } }

"""
let opSwitch = "            switch(op){\n    %%OPS%%\n              default: break;\n            }\n"
let stage1Body = """
        ulong lhash=fnv1a(s,256); ulong prev_lhash=lhash;
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
            ulong off=(tries-1)*256; %%WRITE%%
            if(tries>276 || (s[255]>=0xf0 && tries>260)) break;
        }
        uint dlen=uint((tries-4)*256 + (((ulong(s[253])<<8)|ulong(s[254]))&0x3ffUL));
        lens[gid]=dlen;
"""
if !stage1Body.contains(opSwitch) { fputs("stage-1 op switch not found: the table step would not be compiled in\n", stderr); exit(2) }
let pre = """
    device const uchar* m = msgs + (ulong)gid*msglen;
    uchar msg[64]; for(uint i=0;i<64;i++) msg[i]=0; for(uint i=0;i<msglen;i++) msg[i]=m[i];
    uchar key[32]; sha256_1blk(msg,msglen,key);
    uchar ctr[16]; for(uint i=0;i<16;i++) ctr[i]=0;
    for(uint blk=0;blk<4;blk++){ uchar b[64]; salsa_core(ctr,key,b); for(uint i=0;i<64;i++) s[blk*64+i]=b[i]; uint u=1; for(uint i=8;i<16;i++){u+=uint(ctr[i]);ctr[i]=uchar(u);u>>=8;} }
    rc4_ksa(&r,s); rc4_prga(&r,s,256);
    device uchar* data = datas + (ulong)gid*datastride;
"""
let k1 = """
kernel void k_s1(device const uchar* msgs [[buffer(0)]], constant uint& msglen [[buffer(1)]], device uchar* datas [[buffer(2)]], constant uint& datastride [[buffer(3)]], device uint* lens [[buffer(4)]], uint gid [[thread_position_in_grid]]){
    uchar s[256]; RC4 r;
\(pre)
\(stage1Body.replacingOccurrences(of: "%%WRITE%%", with: "for(uint kk=0;kk<256;kk++) data[off+kk]=s[kk];"))
}
struct ST { uchar s[256]; RC4 r; uchar pad[6]; }; // 520 bytes: every s is 8-aligned (word loads in the tg hashes)
kernel void k_s1tg(device const uchar* msgs [[buffer(0)]], constant uint& msglen [[buffer(1)]], device uchar* datas [[buffer(2)]], constant uint& datastride [[buffer(3)]], device uint* lens [[buffer(4)]], device const uchar* LUT [[buffer(5)]], uint gid [[thread_position_in_grid]], uint lid [[thread_position_in_threadgroup]], threadgroup ST* tg [[threadgroup(0)]]){
    threadgroup uchar* s = tg[lid].s; threadgroup RC4& r = tg[lid].r;
\(pre)
\(stage1Body.replacingOccurrences(of: opSwitch, with: lutStep).replacingOccurrences(of: "%%WRITE%%", with: "device uint* d32=(device uint*)(data+off); for(uint kk=0;kk<64;kk++) d32[kk]=uint(s[4*kk])|(uint(s[4*kk+1])<<8)|(uint(s[4*kk+2])<<16)|(uint(s[4*kk+3])<<24);"))
}
kernel void k_saissha(device uchar* datas [[buffer(0)]], constant uint& datastride [[buffer(1)]], device const uint* lens [[buffer(2)]],
    device int* TPB [[buffer(3)]], device int* SPB [[buffer(4)]], device int* FQB [[buffer(5)]], device int* BKB [[buffer(6)]], constant uint& poolstride [[buffer(7)]], constant uint& bstride [[buffer(8)]], device uchar* outs [[buffer(9)]], uint gid [[thread_position_in_grid]]){
    device uchar* data = datas + (ulong)gid*datastride; uint dlen=lens[gid];
    device int* TP = TPB + (ulong)gid*poolstride; device int* SP = SPB + (ulong)gid*poolstride;
    device int* FQ = FQB + (ulong)gid*bstride; device int* BK = BKB + (ulong)gid*bstride;
    sais_build(data, dlen, TP, SP, FQ, BK);
    uchar out[32]; sha256_sa(SP, dlen, out);
    device uchar* o = outs + (ulong)gid*32; for(uint i=0;i<32;i++) o[i]=out[i];
}
// existing byte-wise final SHA (sha256_sa), one thread per hash
kernel void k_sha(device int* SAB [[buffer(0)]], constant uint& sstride [[buffer(1)]], device const uint* lens [[buffer(2)]], device uchar* outs [[buffer(3)]], uint gid [[thread_position_in_grid]]){
    uchar out[32]; sha256_sa(SAB + (ulong)gid*sstride, lens[gid], out);
    device uchar* o = outs + (ulong)gid*32; for(uint i=0;i<32;i++) o[i]=out[i];
}
// word-wise final SHA: SA int32 LE bytes -> BE message words = byte-swap; rolling 16-word schedule
static void cmp16(thread uint* H, thread uint* w){
    uint a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(uint i=0;i<64;i++){ uint wi;
        if(i<16) wi=w[i]; else { uint x=w[(i-15)&15], y=w[(i-2)&15]; uint s0=rotr(x,7)^rotr(x,18)^(x>>3); uint s1=rotr(y,17)^rotr(y,19)^(y>>10); wi=w[i&15]+s0+w[(i-7)&15]+s1; w[i&15]=wi; }
        uint S1=rotr(e,6)^rotr(e,11)^rotr(e,25); uint ch=(e&f)^((~e)&g); uint t1=h+S1+ch+KC[i]+wi; uint S0=rotr(a,2)^rotr(a,13)^rotr(a,22); uint mj=(a&b)^(a&c)^(b&c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+S0+mj; }
    H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}
inline uint bsw(uint v){ return (v>>24)|((v>>8)&0xff00u)|((v<<8)&0xff0000u)|(v<<24); }
kernel void k_shaw_r18(device const uint* SAB [[buffer(0)]], constant uint& sstride [[buffer(1)]], device const uint* lens [[buffer(2)]], device uchar* outs [[buffer(3)]], uint gid [[thread_position_in_grid]]){
    device const uint* sa = SAB + (ulong)gid*sstride; uint n=lens[gid];
    uint H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint w[16]; uint nb=n/16;
    for(uint bI=0;bI<nb;bI++){ device const uint4* p=(device const uint4*)(sa+bI*16);
        for(uint q=0;q<4;q++){ uint4 v=p[q]; w[q*4]=bsw(v.x); w[q*4+1]=bsw(v.y); w[q*4+2]=bsw(v.z); w[q*4+3]=bsw(v.w); }
        cmp16(H,w); }
    uint rem=n-nb*16; for(uint i=0;i<16;i++) w[i]=0; for(uint i=0;i<rem;i++) w[i]=bsw(sa[nb*16+i]);
    w[rem]=0x80000000u; ulong bits=(ulong)n*32;
    if(rem>=14){ cmp16(H,w); for(uint i=0;i<16;i++) w[i]=0; }
    w[14]=uint(bits>>32); w[15]=uint(bits); cmp16(H,w);
    device uchar* o = outs + (ulong)gid*32; for(uint i=0;i<8;i++){o[i*4]=uchar(H[i]>>24);o[i*4+1]=uchar(H[i]>>16);o[i*4+2]=uchar(H[i]>>8);o[i*4+3]=uchar(H[i]);}
}
""".replacingOccurrences(of: "%%OPS%%", with: opsReg)
// ===== r20 final SHA: k_shaw with the 64 rounds fully unrolled =====
// k_shaw_r18 indexes its 16-word schedule w[(i-15)&15] with a loop variable, so w lives in per-thread stack memory and
// every round waits on it (r20 measured ~18 us of GPU latency per 64-byte block). Here the rounds are generated
// unrolled, so w0..w15, the state and the round constants are registers/immediates. Same message, same padding, same
// output bytes as k_shaw_r18 (proved by the bench cmp mode and the gsplit GSPLIT_REAL bit-exact tests).
func shaCompressMSL() -> String {
    let K: [UInt32] = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
    var s = "static inline void sha_cmpu(thread uint4& HA, thread uint4& HB, uint w0,uint w1,uint w2,uint w3,uint w4,uint w5,uint w6,uint w7,uint w8,uint w9,uint w10,uint w11,uint w12,uint w13,uint w14,uint w15){\n"
    s += "    uint a=HA.x,b=HA.y,c=HA.z,d=HA.w,e=HB.x,f=HB.y,g=HB.z,h=HB.w;\n"
    // rename instead of shifting: round i's (a..h) are v[(8-i%8+k)%8]
    let names = ["a","b","c","d","e","f","g","h"]
    for i in 0..<64 {
        func r(_ k: Int) -> String { names[((k - i) % 8 + 8) % 8] }
        var wi = "w\(i)"
        if i >= 16 {
            let x = "w\((i-15)&15)", y = "w\((i-2)&15)", c = "w\((i-7)&15)", d = "w\(i&15)"
            s += "    \(d)+=(rotr(\(x),7)^rotr(\(x),18)^(\(x)>>3))+\(c)+(rotr(\(y),17)^rotr(\(y),19)^(\(y)>>10));\n"
            wi = d
        }
        // t1 = h + S1(e) + ch(e,f,g) + K + w ; d += t1 ; h = t1 + S0(a) + maj(a,b,c)   (then the names rotate)
        let (A, B, C, D, E, F, G, H) = (r(0), r(1), r(2), r(3), r(4), r(5), r(6), r(7))
        s += "    { uint t1=\(H)+(rotr(\(E),6)^rotr(\(E),11)^rotr(\(E),25))+((\(E)&\(F))^((~\(E))&\(G)))+0x\(String(K[i], radix: 16))u+\(wi); \(D)+=t1; \(H)=t1+(rotr(\(A),2)^rotr(\(A),13)^rotr(\(A),22))+((\(A)&\(B))^(\(A)&\(C))^(\(B)&\(C))); }\n"
    }
    // after 64 rounds (a multiple of 8) the names are back in place
    s += "    HA+=uint4(a,b,c,d); HB+=uint4(e,f,g,h);\n}\n"
    return s
}
let kShaU = shaCompressMSL() + """
kernel void k_shaw(device const uint* SAB [[buffer(0)]], constant uint& sstride [[buffer(1)]], device const uint* lens [[buffer(2)]], device uchar* outs [[buffer(3)]], uint gid [[thread_position_in_grid]]){
    device const uint* sa = SAB + (ulong)gid*sstride; uint n=lens[gid];
    uint4 HA=uint4(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a), HB=uint4(0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19);
    uint nb=n/16;
    device const uint4* p=(device const uint4*)sa;
    for(uint bI=0;bI<nb;bI++,p+=4){ uint4 v0=p[0],v1=p[1],v2=p[2],v3=p[3];
        sha_cmpu(HA,HB,bsw(v0.x),bsw(v0.y),bsw(v0.z),bsw(v0.w),bsw(v1.x),bsw(v1.y),bsw(v1.z),bsw(v1.w),bsw(v2.x),bsw(v2.y),bsw(v2.z),bsw(v2.w),bsw(v3.x),bsw(v3.y),bsw(v3.z),bsw(v3.w)); }
    // tail: rem (<16) message words, the 0x80 pad word, zeros, and the 64-bit bit length in words 14-15
    uint rem=n-nb*16; device const uint* t=sa+nb*16; uint w[16];
    for(uint i=0;i<16;i++) w[i]= i<rem ? bsw(t[i]) : (i==rem ? 0x80000000u : 0u);
    ulong bits=(ulong)n*32;
    if(rem>=14){ sha_cmpu(HA,HB,w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7],w[8],w[9],w[10],w[11],w[12],w[13],w[14],w[15]);
        for(uint i=0;i<16;i++) w[i]=0; }
    w[14]=uint(bits>>32); w[15]=uint(bits);
    sha_cmpu(HA,HB,w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7],w[8],w[9],w[10],w[11],w[12],w[13],w[14],w[15]);
    device uchar* o = outs + (ulong)gid*32; uint H[8]={HA.x,HA.y,HA.z,HA.w,HB.x,HB.y,HB.z,HB.w};
    for(uint i=0;i<8;i++){o[i*4]=uchar(H[i]>>24);o[i*4+1]=uchar(H[i]>>16);o[i*4+2]=uchar(H[i]>>8);o[i*4+3]=uchar(H[i]);}
}
"""
// ===================== r18 server: shared memory + pipelined command buffers =====================
// usage: gpu_split_server <offMsgs> <offLens> <offOuts> <offDatas> <offSas> <dstride> <sstride|0> <slots> <inflight>
// The shared region is fd 3 (POSIX shm created and unlinked by dero-miner, inherited across exec); its size is fstat'd.
// The Go side owns the layout and passes every offset, so the two can never disagree on it. One MTLBuffer
// (bytesNoCopy, untracked hazards) covers the whole mapping; stage-1 texts are written by the GPU straight into it and
// read zero-copy by the CPU sort. Only 16-byte control words travel over the pipes:
//   stdin  command: [op u32][first u32][count u32][tag u32]
//   stdout reply  : [status u32][gpu_us u32][tag u32][op u32]   (status 0 = ok)
//   op 1: stage 1 (k_s1tg) for slots [first,first+count): msgs -> datas, lens
//   op 2: final SHA (k_shaw) for those slots: sas, lens -> outs
//   op 3 (Round 19, only with <sortLanes> > 0 and a suffix-array region): GPU suffix sort of those slots' texts into
//        their suffix-array slots (sort_ops.metal.inc). The slots are cut into chunks of <sortChunk> texts; each chunk
//        runs as one P0 command buffer plus resumable refinement-round buffers on its own lane queue, with the rounds
//        per buffer adapted so each buffer stays <= ~6 ms of GPU time (the macOS interactivity watchdog kills long
//        buffers on a shared GPU). Status 3 = a buffer failed or a text was refused: the Go side then sorts that batch
//        on the CPU (the texts are only read, never changed). The reply's gpu_us is the sum over all buffers.
// Optional trailing arguments: <sortLanes 0..8> <sortChunk 8..512>; older Go sides pass neither (op 3 refused).
// Up to <inflight> command buffers are in flight at once, round-robin over <inflight> queues, with no CPU wait between
// them (completion handlers answer). Different commands touch disjoint slot ranges, and the Go side reuses a slot only
// after its reply, so untracked hazards are safe and the GPU may overlap consecutive batches. EOF on stdin: drain, exit.
let msl = helpers + tgOverloads(helpers) + lutMSL + k1 + kShaU
let A = CommandLine.arguments
guard A.count >= 10, let offMsgs = Int(A[1]), let offLens = Int(A[2]), let offOuts = Int(A[3]), let offDatas = Int(A[4]),
      let offSas = Int(A[5]), let DSTRIDE = Int(A[6]), let SSTRIDE = Int(A[7]), let SLOTS = Int(A[8]), let INFLIGHT = Int(A[9]),
      INFLIGHT >= 1, INFLIGHT <= 16 else {
    fputs("usage: gpu_split_server offMsgs offLens offOuts offDatas offSas dstride sstride slots inflight (shm on fd 3)\n", stderr); exit(1)
}
var st = stat()
if fstat(3, &st) != 0 { fputs("gpu_split_server: no shared memory on fd 3\n", stderr); exit(5) }
let total = Int(st.st_size)
// sstride 0 = no suffix-array region (CPU final SHA): op 2 is refused
let need = [offMsgs + SLOTS*48, offLens + SLOTS*4, offOuts + SLOTS*32, offDatas + SLOTS*DSTRIDE, SSTRIDE > 0 ? offSas + SLOTS*SSTRIDE*4 : 0].max()!
if need > total || total % Int(getpagesize()) != 0 { fputs("gpu_split_server: layout needs \(need) bytes, shm has \(total)\n", stderr); exit(5) }
guard let mp = mmap(nil, total, PROT_READ|PROT_WRITE, MAP_SHARED, 3, 0), mp != MAP_FAILED else { fputs("mmap failed\n", stderr); exit(6) }
guard let dev = MTLCreateSystemDefaultDevice() else { fputs("no Metal device\n", stderr); exit(1) }
var SORTLANES = A.count >= 11 ? max(0, min(Int(A[10]) ?? 0, 8)) : 0
var SORTK = A.count >= 12 ? max(8, min(Int(A[11]) ?? 64, 512)) : 64
var sortSrc = ""
if SORTLANES > 0 {
    if SSTRIDE == 0 { fputs("gpu_split_server: op 3 needs the suffix-array region; GPU sort off\n", stderr); SORTLANES = 0 }
    else if let src = try? String(contentsOfFile: "sort_ops.metal.inc", encoding: .utf8) { sortSrc = src }
    else { fputs("gpu_split_server: sort_ops.metal.inc missing; GPU sort off\n", stderr); SORTLANES = 0 }
}
var lib: MTLLibrary
do { lib = try dev.makeLibrary(source: msl + sortSrc, options: nil) } catch {
    if sortSrc.isEmpty { fputs("MSL ERR:\n\(error)\n", stderr); exit(2) }
    fputs("gpu_split_server: sort kernels do not compile; GPU sort off:\n\(error)\n", stderr); SORTLANES = 0
    do { lib = try dev.makeLibrary(source: msl, options: nil) } catch { fputs("MSL ERR:\n\(error)\n", stderr); exit(2) }
}
func pso(_ n: String) -> MTLComputePipelineState { try! dev.makeComputePipelineState(function: lib.makeFunction(name: n)!) }
let pS1tg = pso("k_s1tg"), pShaW = pso("k_shaw")
// r22: the op tables (k_lut), built once on the GPU into a private buffer the stage-1 kernel reads at index 5
let lutBuf = dev.makeBuffer(length: 256*3*256, options: .storageModePrivate)!
do {
    let q = dev.makeCommandQueue()!, cb = q.makeCommandBuffer()!, e = cb.makeComputeCommandEncoder()!
    let p = pso("k_lut")
    e.setComputePipelineState(p); e.setBuffer(lutBuf, offset: 0, index: 0)
    e.dispatchThreads(MTLSize(width: 256*3*256, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: min(256, p.maxTotalThreadsPerThreadgroup), height: 1, depth: 1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    if cb.status != .completed { fputs("gpu_split_server: op tables failed: \(String(describing: cb.error))\n", stderr); exit(2) }
}
guard let shm = dev.makeBuffer(bytesNoCopy: mp, length: total, options: [.storageModeShared, .hazardTrackingModeUntracked], deallocator: nil) else {
    fputs("bytesNoCopy failed (total=\(total))\n", stderr); exit(7)
}
// r20: stage-1 threadgroup width. k_s1tg is latency-bound: every lane runs its own random op, so a SIMD-group executes
// the union of its lanes' op bodies and hash loops, and the 520-byte per-thread threadgroup state caps residency per
// core. Narrower threadgroups (8 threads; the rest of the SIMD-group idles) cut that union and fit more groups per core:
// measured x1.4-1.5 stage-1 throughput vs 32 (A/B in the r20 gpukernels report). Results do not depend on it (each
// thread owns its own slice of threadgroup memory). GSPLIT_S1_TGW=4|8|16|32 overrides it for tuning.
var s1TGW = 8
if let v = ProcessInfo.processInfo.environment["GSPLIT_S1_TGW"], let w = Int(v), [4, 8, 16, 32].contains(w) { s1TGW = w }
let queues = (0..<INFLIGHT).map { _ in dev.makeCommandQueue()! }
let slotsFree = DispatchSemaphore(value: INFLIGHT)
var ml = UInt32(48), ds = UInt32(DSTRIDE), ss = UInt32(SSTRIDE)
func reply(_ status: UInt32, _ us: UInt32, _ tag: UInt32, _ op: UInt32) {
    var r: [UInt32] = [status, us, tag, op]
    // 16 bytes < PIPE_BUF: one write(2) is atomic, so completion handlers on different threads never interleave
    let w = r.withUnsafeMutableBytes { write(1, $0.baseAddress, 16) }
    if w != 16 { exit(9) }
}
// ---- op 3: GPU suffix sort on <SORTLANES> lanes (Round 19) ----
let NSS = DSTRIDE // text and rank stride of the sort kernels (the kernels refuse a text longer than it)
let LCAP = (NSS/2+1)+(NSS/5+1)+(NSS/9+1)+(NSS/17+1)+(NSS/129+1)
final class Op3 { let tag: UInt32; var left: Int; var us = 0.0; var failed = false; init(_ t: UInt32, _ l: Int) { tag = t; left = l } }
struct Chunk { let op: Op3; let first: Int; let k: Int }
final class Lane {
    let q: MTLCommandQueue; let rk, sgl, ga, gb, st: MTLBuffer; var R = 1
    init(_ dev: MTLDevice, _ k: Int, _ ns: Int, _ lcap: Int) {
        q = dev.makeCommandQueue()!
        rk = dev.makeBuffer(length: k*ns*8, options: .storageModePrivate)!
        sgl = dev.makeBuffer(length: k*ns*4, options: .storageModePrivate)!
        ga = dev.makeBuffer(length: k*lcap*8, options: .storageModePrivate)!
        gb = dev.makeBuffer(length: k*lcap*8, options: .storageModePrivate)!
        st = dev.makeBuffer(length: k*32, options: .storageModeShared)!
    }
}
let sortMu = NSLock()
var chunks: [Chunk] = []
let chunkSem = DispatchSemaphore(value: 0)
let opsLive = DispatchGroup()
let SORTKMAX = SORTK // lanes are sized for the starting chunk; the adaptive chunk only shrinks
var sStat = (chunks: 0, cbs: 0, texts: 0, fails: 0, maxMs: 0.0, sumMs: 0.0, last: Date())
var sAll = (texts: 0, cbs: 0, over8: 0, maxMs: 0.0) // cumulative, printed at exit
func sortNote(_ ms: Double) {
    sortMu.lock()
    sStat.cbs += 1; sStat.sumMs += ms; if ms > sStat.maxMs { sStat.maxMs = ms }
    sAll.cbs += 1; if ms > sAll.maxMs { sAll.maxMs = ms }; if ms > 8 { sAll.over8 += 1 }
    sortMu.unlock()
}
// one command buffer of one sort kernel over chunk c; nil = the buffer failed (watchdog, recovery)
func sortCB(_ lane: Lane, _ p: MTLComputePipelineState, _ c: Chunk, _ maxR: UInt32) -> Double? {
    let cb = lane.q.makeCommandBuffer()!
    let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p)
    e.setBuffer(shm, offset: offDatas + c.first*DSTRIDE, index: 0)
    e.setBuffer(shm, offset: offLens + c.first*4, index: 1)
    e.setBuffer(shm, offset: offSas + c.first*SSTRIDE*4, index: 2)
    e.setBuffer(lane.rk, offset: 0, index: 3); e.setBuffer(lane.sgl, offset: 0, index: 4)
    e.setBuffer(lane.ga, offset: 0, index: 5); e.setBuffer(lane.gb, offset: 0, index: 6); e.setBuffer(lane.st, offset: 0, index: 7)
    var ns = UInt32(NSS), sst = UInt32(SSTRIDE), mr = maxR
    e.setBytes(&ns, length: 4, index: 8); e.setBytes(&sst, length: 4, index: 9); e.setBytes(&mr, length: 4, index: 10)
    e.dispatchThreadgroups(MTLSize(width: c.k, height: 1, depth: 1),
                           threadsPerThreadgroup: MTLSize(width: min(1024, p.maxTotalThreadsPerThreadgroup), height: 1, depth: 1))
    e.endEncoding()
    cb.commit()
    cb.waitUntilCompleted()
    if cb.status != .completed { fputs("SORT CB FAILED \(String(describing: cb.error))\n", stderr); return nil }
    let t = max(cb.gpuEndTime - cb.gpuStartTime, 0)
    sortNote(t * 1000)
    return t
}
func sortChunk(_ lane: Lane, _ pP0: MTLComputePipelineState, _ pR: MTLComputePipelineState, _ c: Chunk) -> (Bool, Double) {
    guard let t0 = sortCB(lane, pP0, c, 0) else { return (false, 0) }
    var gpu = t0
    if t0 > 0.006 { sortMu.lock(); SORTK = max(8, SORTK/2); sortMu.unlock() }
    let st = lane.st.contents().bindMemory(to: UInt32.self, capacity: c.k*8)
    for _ in 0..<64 {
        guard let t = sortCB(lane, pR, c, UInt32(lane.R)) else { return (false, gpu) }
        gpu += t
        // adapt the rounds per buffer (and, at one round, the chunk) so every buffer stays short. Round 19 live run
        // (shared, 99%-busy GPU): growing to 8 rounds per buffer on the cheap late rounds let 8.9% of buffers exceed
        // 8 ms (max 72.6 ms), so the rounds per buffer are capped at 4, step down above 4 ms and grow only below 1.5 ms.
        if t > 0.004 { if lane.R > 1 { lane.R = max(1, lane.R / 2) } else if t > 0.006 { sortMu.lock(); SORTK = max(8, SORTK/2); sortMu.unlock() } }
        else if t < 0.0015 && lane.R < 4 { lane.R += 1 }
        var pending = 0
        for i in 0..<c.k { let s = st[i*8+6]; if s == 2 { return (false, gpu) }; if s == 0 { pending += 1 } }
        if pending == 0 { return (true, gpu) }
    }
    return (false, gpu)
}
if SORTLANES > 0 {
    let pP0 = pso("sg_p0"), pR = pso("sg_rounds")
    for _ in 0..<SORTLANES {
        let lane = Lane(dev, SORTKMAX, NSS, LCAP)
        Thread {
            while true { autoreleasepool { // r21 merge: drain per chunk like the command loop (storageops leak fix)
                chunkSem.wait()
                sortMu.lock(); let c = chunks.removeFirst(); sortMu.unlock()
                let (ok, us) = sortChunk(lane, pP0, pR, c)
                sortMu.lock()
                c.op.us += us; if !ok { c.op.failed = true; sStat.fails += 1 }
                c.op.left -= 1; sStat.chunks += 1; sStat.texts += c.k; sAll.texts += c.k
                let done = c.op.left == 0
                var line = ""
                if Date().timeIntervalSince(sStat.last) >= 60 {
                    line = String(format: "gpu_split_server sort: chunks=%d texts=%d cbs=%d mean_cb_ms=%.2f max_cb_ms=%.2f fails=%d chunk=%d rounds_per_cb=%d\n",
                                  sStat.chunks, sStat.texts, sStat.cbs, sStat.sumMs/Double(max(sStat.cbs, 1)), sStat.maxMs, sStat.fails, SORTK, lane.R)
                    sStat = (0, 0, 0, 0, 0, 0, Date())
                }
                sortMu.unlock()
                if !line.isEmpty { fputs(line, stderr) }
                if done {
                    reply(c.op.failed ? 3 : 0, UInt32(min(c.op.us * 1e6, 4e9)), c.op.tag, 3)
                    opsLive.leave()
                }
            } }
        }.start()
    }
}
fputs("gpu_split_server ready slots=\(SLOTS) shm=\(total) inflight=\(INFLIGHT) sortLanes=\(SORTLANES) sortChunk=\(SORTK) s1_tgw=\(s1TGW) kernels=r22\n", stderr)
var cmd = [UInt32](repeating: 0, count: 4)
var rr = 0
while fread(&cmd, 4, 4, stdin) == 4 {
    let op = cmd[0], first = Int(cmd[1]), n = Int(cmd[2]), tag = cmd[3]
    if first < 0 || n <= 0 || first + n > SLOTS || (op != 1 && op != 2 && op != 3) || (op == 2 && SSTRIDE == 0) || (op == 3 && SORTLANES == 0) {
        reply(1, 0, tag, op); continue
    }
    if op == 3 {
        sortMu.lock()
        let k = min(SORTK, SORTKMAX)
        let nch = (n + k - 1) / k
        let o = Op3(tag, nch)
        var f = first
        while f < first + n { chunks.append(Chunk(op: o, first: f, k: min(k, first + n - f))); f += k }
        sortMu.unlock()
        opsLive.enter()
        for _ in 0..<nch { chunkSem.signal() }
        continue
    }
    slotsFree.wait()
    // r21 (storageops): this loop never returns to a run loop, so the autoreleased command buffer and encoder of every
    // command stayed in the main thread's pool forever: the live server's physical footprint grew ~21 MB/h
    // (21M -> 29M in 23 min, top MEM, 2026-10-28). One pool per command releases them when the command is committed.
    autoreleasepool {
        let q = queues[rr % INFLIGHT]; rr += 1
        let cb = q.makeCommandBuffer()!
        let e = cb.makeComputeCommandEncoder()!
        if op == 1 {
            e.setComputePipelineState(pS1tg)
            e.setBuffer(shm, offset: offMsgs + first*48, index: 0); e.setBytes(&ml, length: 4, index: 1)
            e.setBuffer(shm, offset: offDatas + first*DSTRIDE, index: 2); e.setBytes(&ds, length: 4, index: 3)
            e.setBuffer(shm, offset: offLens + first*4, index: 4)
            e.setBuffer(lutBuf, offset: 0, index: 5) // r22 op tables
            e.setThreadgroupMemoryLength(520*s1TGW, index: 0) // MemoryLayout of ST (520) x the threadgroup width
        } else {
            e.setComputePipelineState(pShaW)
            e.setBuffer(shm, offset: offSas + first*SSTRIDE*4, index: 0); e.setBytes(&ss, length: 4, index: 1)
            e.setBuffer(shm, offset: offLens + first*4, index: 2); e.setBuffer(shm, offset: offOuts + first*32, index: 3)
        }
        e.dispatchThreads(MTLSize(width: n, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: min(n, op == 1 ? s1TGW : 32), height: 1, depth: 1))
        e.endEncoding()
        cb.addCompletedHandler { c in
            let ok: UInt32 = c.status == .completed ? 0 : 2
            if ok != 0 { fputs("CB FAILED \(String(describing: c.error))\n", stderr) }
            reply(ok, UInt32(min(max(c.gpuEndTime - c.gpuStartTime, 0) * 1e6, 4e9)), tag, op)
            slotsFree.signal()
        }
        cb.commit()
    }
}
for _ in 0..<INFLIGHT { slotsFree.wait() } // drain: every reply is written before exit
opsLive.wait()
if sAll.cbs > 0 {
    fputs(String(format: "gpu_split_server sort total: texts=%d cbs=%d max_cb_ms=%.2f cbs_over_8ms=%d chunk=%d\n", sAll.texts, sAll.cbs, sAll.maxMs, sAll.over8, SORTK), stderr)
}
exit(0)
