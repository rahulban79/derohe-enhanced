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

let kernel = """
kernel void full_hash(device const uchar* msgs [[buffer(0)]], constant uint& msglen [[buffer(1)]], constant uint& stride [[buffer(2)]],
                      device uchar* outs [[buffer(3)]],
                      device uchar* datas [[buffer(4)]], constant uint& datastride [[buffer(5)]],
                      device int* TPB [[buffer(6)]], device int* SPB [[buffer(7)]], device int* FQB [[buffer(8)]], device int* BKB [[buffer(9)]], constant uint& poolstride [[buffer(10)]], constant uint& bstride [[buffer(11)]],
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
    device int* TP = TPB + (ulong)gid*poolstride; device int* SP = SPB + (ulong)gid*poolstride;
    device int* FQ = FQB + (ulong)gid*bstride; device int* BK = BKB + (ulong)gid*bstride;
    sais_build(data, dlen, TP, SP, FQ, BK);
    uchar out[32]; sha256_sa(SP, dlen, out);
    device uchar* o = outs + (ulong)gid*32; for(uint i=0;i<32;i++) o[i]=out[i];
}
""".replacingOccurrences(of: "%%OPS%%", with: opsInc)

let msl = helpers + kernel
guard let dev = MTLCreateSystemDefaultDevice() else { exit(1) }
let q = dev.makeCommandQueue()!
let lib: MTLLibrary
do { lib = try dev.makeLibrary(source: msl, options: nil) } catch { print("MSL ERR:\n\(error)"); exit(2) }
let pso = try dev.makeComputePipelineState(function: lib.makeFunction(name:"full_hash")!)
let DSTRIDE=278*256, PSTRIDE=2*71200, BSTRIDE=9216
if CommandLine.arguments.contains("server") { runServer(); exit(0) }
print("full_hash kernel compiled OK.")

func readExactly(_ n: Int) -> Data? {
    var buf = Data(); buf.reserveCapacity(n)
    while buf.count < n {
        let chunk = FileHandle.standardInput.readData(ofLength: n - buf.count)
        if chunk.isEmpty { return nil }  // EOF
        buf.append(chunk)
    }
    return buf
}
// Server mode: stdin protocol [uint32 count][count*48 blob bytes] -> stdout [count*32 hash bytes], looped.
// The Go --gpu worker drives this; blobs are the 48-byte MINIBLOCK work with varied nonce.
func runServer() {
    let maxN = 8192
    let msgs = dev.makeBuffer(length: maxN*48, options:.storageModeShared)!
    let ob   = dev.makeBuffer(length: maxN*32, options:.storageModeShared)!
    let da   = dev.makeBuffer(length: DSTRIDE*maxN, options:.storageModePrivate)!
    let TP   = dev.makeBuffer(length: PSTRIDE*4*maxN, options:.storageModePrivate)!
    let SP   = dev.makeBuffer(length: PSTRIDE*4*maxN, options:.storageModePrivate)!
    let FQ   = dev.makeBuffer(length: BSTRIDE*4*maxN, options:.storageModePrivate)!
    let BK   = dev.makeBuffer(length: BSTRIDE*4*maxN, options:.storageModePrivate)!
    FileHandle.standardError.write("gpu server ready (maxN=\(maxN))\n".data(using:.utf8)!)
    while true {
        guard let cd = readExactly(4) else { break }
        let count = Int(cd.withUnsafeBytes { $0.load(as: UInt32.self) })
        if count <= 0 || count > maxN { break }
        guard let blobs = readExactly(count*48) else { break }
        blobs.withUnsafeBytes { (bp: UnsafeRawBufferPointer) in msgs.contents().copyMemory(from: bp.baseAddress!, byteCount: count*48) }
        var ml=UInt32(48); var st=UInt32(48); var ds=UInt32(DSTRIDE); var ps=UInt32(PSTRIDE); var bsv=UInt32(BSTRIDE)
        let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(pso); e.setBuffer(msgs,offset:0,index:0); e.setBytes(&ml,length:4,index:1); e.setBytes(&st,length:4,index:2)
        e.setBuffer(ob,offset:0,index:3); e.setBuffer(da,offset:0,index:4); e.setBytes(&ds,length:4,index:5)
        e.setBuffer(TP,offset:0,index:6); e.setBuffer(SP,offset:0,index:7); e.setBuffer(FQ,offset:0,index:8); e.setBuffer(BK,offset:0,index:9); e.setBytes(&ps,length:4,index:10); e.setBytes(&bsv,length:4,index:11)
        e.dispatchThreads(MTLSize(width:count,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(count,32),height:1,depth:1))
        e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
        if cb.status != .completed { FileHandle.standardError.write("gpu batch failed\n".data(using:.utf8)!); break }
        FileHandle.standardOutput.write(Data(bytes: ob.contents(), count: count*32))
    }
}

let inputs: [(String,[UInt8])] = [
 ("a",[UInt8]("a".utf8)),("ab",[UInt8]("ab".utf8)),("abc",[UInt8]("abc".utf8)),("abcd",[UInt8]("abcd".utf8)),
 ("abcde",[UInt8]("abcde".utf8)),("abcdef",[UInt8]("abcdef".utf8)),("abcdefg",[UInt8]("abcdefg".utf8)),
 ("abcdefgh",[UInt8]("abcdefgh".utf8)),("abcdefghi",[UInt8]("abcdefghi".utf8)),("abcdefghij",[UInt8]("abcdefghij".utf8)),
 ("48x00",[UInt8](repeating:0,count:48))]
for (idx,(label,inp)) in inputs.enumerated() {
    let stride=max(inp.count,1)
    let mbuf=dev.makeBuffer(bytes: inp.isEmpty ? [0]:inp, length:stride, options:.storageModeShared)!
    let ob=dev.makeBuffer(length:32, options:.storageModeShared)!
    let da=dev.makeBuffer(length:DSTRIDE, options:.storageModePrivate)!
    let TP=dev.makeBuffer(length:PSTRIDE*4, options:.storageModePrivate)!
    let SP=dev.makeBuffer(length:PSTRIDE*4, options:.storageModePrivate)!
    let FQ=dev.makeBuffer(length:BSTRIDE*4, options:.storageModePrivate)!
    let BK=dev.makeBuffer(length:BSTRIDE*4, options:.storageModePrivate)!
    var ml=UInt32(inp.count); var st=UInt32(stride); var ds=UInt32(DSTRIDE); var ps=UInt32(PSTRIDE); var bsv=UInt32(BSTRIDE)
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(mbuf,offset:0,index:0); e.setBytes(&ml,length:4,index:1); e.setBytes(&st,length:4,index:2)
    e.setBuffer(ob,offset:0,index:3); e.setBuffer(da,offset:0,index:4); e.setBytes(&ds,length:4,index:5)
    e.setBuffer(TP,offset:0,index:6); e.setBuffer(SP,offset:0,index:7); e.setBuffer(FQ,offset:0,index:8); e.setBuffer(BK,offset:0,index:9); e.setBytes(&ps,length:4,index:10); e.setBytes(&bsv,length:4,index:11)
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
    let scratchGB = Double(N) * Double(DSTRIDE + PSTRIDE*(4+4) + BSTRIDE*(4+4)) / 1e9
    guard let mbuf=dev.makeBuffer(bytes:inp2,length:inp2.count,options:.storageModeShared),
          let ob=dev.makeBuffer(length:N*32,options:.storageModeShared),
          let da=dev.makeBuffer(length:DSTRIDE*N,options:.storageModePrivate),
          let TP=dev.makeBuffer(length:PSTRIDE*4*N,options:.storageModePrivate),
          let SP=dev.makeBuffer(length:PSTRIDE*4*N,options:.storageModePrivate),
          let FQ=dev.makeBuffer(length:BSTRIDE*4*N,options:.storageModePrivate),
          let BK=dev.makeBuffer(length:BSTRIDE*4*N,options:.storageModePrivate) else { print(String(format:"%7d  alloc-fail %.1fGB",N,scratchGB)); continue }
    var ml=UInt32(inp2.count); var st=UInt32(inp2.count); var ds=UInt32(DSTRIDE); var ps=UInt32(PSTRIDE); var bsv=UInt32(BSTRIDE)
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(mbuf,offset:0,index:0); e.setBytes(&ml,length:4,index:1); e.setBytes(&st,length:4,index:2)
    e.setBuffer(ob,offset:0,index:3); e.setBuffer(da,offset:0,index:4); e.setBytes(&ds,length:4,index:5)
    e.setBuffer(TP,offset:0,index:6); e.setBuffer(SP,offset:0,index:7); e.setBuffer(FQ,offset:0,index:8); e.setBuffer(BK,offset:0,index:9); e.setBytes(&ps,length:4,index:10); e.setBytes(&bsv,length:4,index:11)
    e.dispatchThreads(MTLSize(width:N,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(N,32),height:1,depth:1))
    e.endEncoding(); let t0=Date(); cb.commit(); cb.waitUntilCompleted(); let dt=Date().timeIntervalSince(t0)
    let ok = cb.status == .completed && cb.error == nil
    print(String(format:"%7d threads  %.2fs  %8.1f H/s  scratch=%.1fGB  ok=%@", N, dt, Double(N)/dt, scratchGB, ok ? "Y":"KILL"))
    if !ok { break }
}
