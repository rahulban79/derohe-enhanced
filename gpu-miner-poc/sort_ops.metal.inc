// sort_ops.metal.inc -- block-per-hash suffix sort of AstroBWTv3 stage-1 texts for gpu_split_server op 3 (Round 19).
// Clean-room (derohe Round 18 spike gpu-miner-poc-r18/sa_r18.metal + its CPU model pdsort; no third-party or other
// miner code), changed for the split server: the text/rank stride (NS) and the suffix-array stride (SS) are separate,
// and the refinement rounds are RESUMABLE: sg_p0 runs the 12-bit counting sort, sg_rounds runs at most maxR rounds per
// dispatch and keeps its progress in state[], so every command buffer stays a few milliseconds long.
// One threadgroup sorts one text in device memory:
//   P0 counting sort by a 12-bit key (byte0, high nibble of byte1; 4096 bins in threadgroup memory, atomic scatter)
//   P1 sort each P0 group by low nibble of byte1 + bytes 2..8 (60-bit key) -> equal-9-prefix groups
//   Pk sort each group by rank[p+h]+h, or n-p-1 if p+h >= n, h = 9, 18, 36, ... until no group of size >= 2 remains
//   (bytes past the end read as 0; the tail key makes that exact).
// The output is checked: the split engine's self-test (start and every respawn) compares GPU-sorted hashes with
// astrobwtv3.AstroBWTv3, a sampled CPU audit re-hashes GPU-sorted results, and every winning share is re-hashed.

#define NB 4096u   // byte0, high nibble of byte1 (bytes past the end read as 0)
#ifndef P1WIDE
#define P1WIDE 1
#endif
#if P1WIDE
typedef ulong K1;   // P1 key: low nibble of byte1 + bytes 2..8 (60 bits) -> 9-byte prefix
#define H0 9u
#else
typedef uint K1;    // P1 key: low nibble of byte1 + bytes 2..4 (28 bits)  -> 5-byte prefix
#define H0 5u
#endif
struct G { int s; int l; };

inline uint tb(device const uchar* t, uint n, uint i){ return i<n ? uint(t[i]) : 0u; }
inline uint k2(device const uchar* t, uint n, uint p){ return (uint(t[p])<<4) | (tb(t,n,p+1u)>>4); }
inline K1 k6(device const uchar* t, uint n, uint p){ K1 k=K1(tb(t,n,p+1u)&15u); for(uint i=2;i<H0;i++){ k=(k<<8)|K1(tb(t,n,p+i)); } return k; }
inline ulong shx(ulong x, ushort m){ uint2 u=as_type<uint2>(x); u.x=simd_shuffle_xor(u.x,m); u.y=simd_shuffle_xor(u.y,m); return as_type<ulong>(u); }
inline uint  shx(uint x, ushort m){ return simd_shuffle_xor(x,m); }
inline ulong shup(ulong x, ushort d){ uint2 u=as_type<uint2>(x); u.x=simd_shuffle_up(u.x,d); u.y=simd_shuffle_up(u.y,d); return as_type<ulong>(u); }
inline uint  shup(uint x, ushort d){ return simd_shuffle_up(x,d); }
inline ulong shb(ulong x, ushort l){ uint2 u=as_type<uint2>(x); u.x=simd_shuffle(u.x,l); u.y=simd_shuffle(u.y,l); return as_type<ulong>(u); }
inline uint  shb(uint x, ushort l){ return simd_shuffle(x,l); }
template<typename K> inline K kmax();
template<> inline ulong kmax<ulong>(){ return ~0ul; }
template<> inline uint  kmax<uint>(){ return ~0u; }

struct Ctx {
    device const uchar* t; uint n; uint h; device int* SA; device const int* RKr; device int* RKw; device int* RKo; device G* nxt;
    threadgroup atomic_uint* cnt; uint o1, o2, o3, o4; device uint* SGL; threadgroup atomic_uint* sgc;
};
inline void emit(thread const Ctx& c, int s, int l){
    uint cl = l<=4 ? 0u : l<=8 ? 1u : l<=16 ? 2u : l<=128 ? 3u : 4u;
    uint off = cl==0u ? 0u : cl==1u ? c.o1 : cl==2u ? c.o2 : cl==3u ? c.o3 : c.o4;
    uint q = atomic_fetch_add_explicit(&c.cnt[cl],1u,memory_order_relaxed);
    c.nxt[off+q] = G{s,l};
}
// a singleton is final: queue it, and after the round's barrier copy its rank into the other parity too
// Rank arrays are stored COLUMN-MAJOR over the 256-byte blocks stage 1 writes: rki(p) = (p mod 256)*RKB + p/256.
// Group members are mostly the same column of consecutive blocks (p, p+256, ...), so their rank reads (p+h) and
// writes (p) land on adjacent words instead of one cache line each.
#ifndef RKCOL
#define RKCOL 1
#endif
#define RKB 278u
inline uint rki(uint p){ return RKCOL ? (p&255u)*RKB + (p>>8) : p; }
inline void setRank(thread const Ctx& c, uint p, int r, bool single){ c.RKw[rki(p)]=r; if(single){ uint q=atomic_fetch_add_explicit(c.sgc,1u,memory_order_relaxed); c.SGL[q]=p; } }
template<typename K> inline K keyAt(thread const Ctx& c, int j){ return K(0); }
struct KD { uint v; };   // doubling-round key: rank[p+h]+h, or n-p-1 when p+h >= n (shorter tail first)
inline bool operator>(KD a, KD b){ return a.v>b.v; } inline bool operator<(KD a, KD b){ return a.v<b.v; } inline bool operator!=(KD a, KD b){ return a.v!=b.v; } inline bool operator==(KD a, KD b){ return a.v==b.v; }
inline KD shx(KD x, ushort m){ return KD{simd_shuffle_xor(x.v,m)}; } inline KD shup(KD x, ushort d){ return KD{simd_shuffle_up(x.v,d)}; } inline KD shb(KD x, ushort l){ return KD{simd_shuffle(x.v,l)}; }
template<> inline KD kmax<KD>(){ return KD{~0u}; }
template<> inline K1 keyAt<K1>(thread const Ctx& c, int j){ return k6(c.t,c.n,uint(c.SA[j])); }
template<> inline KD keyAt<KD>(thread const Ctx& c, int j){ uint p=uint(c.SA[j]); return KD{(p+c.h<c.n)? uint(c.RKr[rki(p+c.h)])+c.h : c.n-p-1u}; }

// one SIMD group sorts 32/W groups of <= W members at once: lane = segment*W + r, every shuffle distance is < W so
// segments never mix; heads, a segmented max-scan and the run ends are all computed inside the W-lane segment.
template<uint W, typename K>
static void ssortW(thread const Ctx& c, device const G* list, uint cnt, uint gbase, ushort lane){
    const uint seg=lane/W, r=lane%W; const uint gi=gbase+seg;
    G g = gi<cnt ? list[gi] : G{0,0};
    K k; uint v;
    if(int(r)<g.l){ v=uint(c.SA[g.s+int(r)]); k=keyAt<K>(c,g.s+int(r)); } else { v=0u; k=kmax<K>(); }
    for(uint kk=2;kk<=W;kk<<=1) for(uint j=kk>>1;j>0;j>>=1){
        K ok=shx(k,ushort(j)); uint ov=simd_shuffle_xor(v,ushort(j));
        bool asc=(r&kk)==0u; bool lower=(r&j)==0u;
        bool take = (lower==asc) ? (ok<k) : (ok>k);
        if(take){ k=ok; v=ov; } }
    K pk=shup(k,1); bool head=(r==0u)||(k!=pk);
    uint hv=head? r:0u;
    for(ushort d=1; d<W; d<<=1){ uint o=simd_shuffle_up(hv,d); if(r>=d) hv=max(hv,o); }
    uint ns=simd_shuffle_down(hv,1);
    bool last=(int(r)==g.l-1)||(r+1u<W && ns!=hv);
    if(int(r)<g.l){ c.SA[g.s+int(r)]=int(v); setRank(c,v,g.s+int(hv),last && hv==r);
        if(last && r>hv) emit(c,g.s+int(hv),int(r-hv+1u)); }
}

// one SIMD group sorts one group of <= 32*E members
template<uint E, typename K>
static void ssort(thread const Ctx& c, G g, ushort lane){
    K k[E]; uint v[E];
    for(uint e=0;e<E;e++){ uint i=e*32u+lane;
        if(int(i)<g.l){ v[e]=uint(c.SA[g.s+int(i)]); k[e]=keyAt<K>(c,g.s+int(i)); } else { k[e]=kmax<K>(); v[e]=0u; } }
    for(uint kk=2;kk<=32u*E;kk<<=1){
        for(uint j=kk>>1;j>0;j>>=1){
            if(j>=32u){ uint je=j>>5;
                for(uint e=0;e<E;e++){ if((e&je)==0u){ uint e2=e|je; uint i=e*32u+lane; bool asc=(i&kk)==0u;
                    bool sw = asc ? (k[e]>k[e2]) : (k[e]<k[e2]);
                    if(sw){ K tk=k[e]; k[e]=k[e2]; k[e2]=tk; uint tv=v[e]; v[e]=v[e2]; v[e2]=tv; } } }
            } else {
                for(uint e=0;e<E;e++){ K ok=shx(k[e],ushort(j)); uint ov=simd_shuffle_xor(v[e],ushort(j));
                    uint i=e*32u+lane; bool asc=(i&kk)==0u; bool lower=(lane&j)==0u;
                    bool take = (lower==asc) ? (ok<k[e]) : (ok>k[e]);
                    if(take){ k[e]=ok; v[e]=ov; } }
            }
        }
    }
    uint st[E]; uint carry=0;
    for(uint e=0;e<E;e++){ uint i=e*32u+lane;
        K pk=shup(k[e],1); K lp=shb(k[e>0?e-1:0],31); if(lane==0) pk=lp;
        bool head=(i==0u)||(k[e]!=pk);
        uint hv=head? i:0u;
        for(ushort d=1; d<32; d<<=1){ uint o=simd_shuffle_up(hv,d); if(lane>=d) hv=max(hv,o); }
        hv=max(hv,carry); st[e]=hv; carry=simd_shuffle(hv,31); }
    for(uint e=0;e<E;e++){ uint i=e*32u+lane;
        uint ns=simd_shuffle_down(st[e],1); uint nf=simd_shuffle(st[e+1<E?e+1:e],0); if(lane==31) ns=nf;
        bool last=(int(i)==g.l-1)||(ns!=st[e]);
        if(int(i)<g.l){ c.SA[g.s+int(i)]=int(v[e]); uint len=i-st[e]+1u;
            setRank(c,v[e],g.s+int(st[e]),last && st[e]==i);
            if(last && len>=2u) emit(c,g.s+int(st[e]),int(len)); } }
}

// the whole threadgroup sorts one big group in place (flip-bitonic; indices >= L behave as +inf)
template<typename K>
static void bsort(thread const Ctx& c, G g, uint tid, uint ntg){
    uint L=uint(g.l); uint P=1; while(P<L) P<<=1;
    for(uint kk=2;kk<=P;kk<<=1){ for(uint j=kk>>1;j>0;j>>=1){
        for(uint q=tid;q<P/2u;q+=ntg){ uint a,b;
            if(j==(kk>>1)){ uint blk=q/j, x=q%j; a=blk*kk+x; b=blk*kk+kk-1u-x; } else { a=(q/j)*2u*j+(q%j); b=a+j; }
            if(b<L){ int ia=g.s+int(a), ib=g.s+int(b); K ka=keyAt<K>(c,ia), kb=keyAt<K>(c,ib);
                if(ka>kb){ int tv=c.SA[ia]; c.SA[ia]=c.SA[ib]; c.SA[ib]=tv; } } }
        threadgroup_barrier(mem_flags::mem_device); } }
    for(uint i=tid;i<L;i+=ntg){ int ii=g.s+int(i); K ki=keyAt<K>(c,ii);
        if(i==0u || keyAt<K>(c,ii-1)!=ki){ uint e=i+1u; while(e<L && keyAt<K>(c,g.s+int(e))==ki) e++;
            for(uint q=i;q<e;q++) setRank(c,uint(c.SA[g.s+int(q)]),g.s+int(i),e-i==1u);
            if(e-i>=2u) emit(c,g.s+int(i),int(e-i)); } }
    threadgroup_barrier(mem_flags::mem_device|mem_flags::mem_threadgroup);
}

template<typename K>
static void phaseB(thread const Ctx& c, device const G* cur, thread const uint* cc, uint tid, uint ntg, ushort sid, ushort lane, ushort nsg){
    for(uint gb=sid*8u; gb<cc[0]; gb+=nsg*8u) ssortW<4,K>(c,cur,cc[0],gb,lane);
    for(uint gb=sid*4u; gb<cc[1]; gb+=nsg*4u) ssortW<8,K>(c,cur+c.o1,cc[1],gb,lane);
    for(uint gb=sid*2u; gb<cc[2]; gb+=nsg*2u) ssortW<16,K>(c,cur+c.o2,cc[2],gb,lane);
    for(uint gi=sid; gi<cc[3]; gi+=nsg){ G g=cur[c.o3+gi];
        if(g.l<=32) ssort<1,K>(c,g,lane); else if(g.l<=64) ssort<2,K>(c,g,lane); else ssort<4,K>(c,g,lane); }
    threadgroup_barrier(mem_flags::mem_device|mem_flags::mem_threadgroup);
    for(uint gi=0; gi<cc[4]; gi++) bsort<K>(c,cur[c.o4+gi],tid,ntg);
}
// ---- r19 split-server variant: separate text/rank stride (NS) and suffix-array stride (SS); resumable rounds ----
struct Lay { device int* RK0; device int* RK1; device G* GA; device G* GB; };
inline Ctx mkctx(device const uchar* texts, device const uint* lens, device int* SAb, device int* RKb, device uint* SGLb,
                 device G* GAb, device G* GBb, uint NS, uint SS, uint tg, threadgroup atomic_uint* cnt, threadgroup atomic_uint* sgc, thread Lay& L){
    const uint o1=NS/2u+1u, o2=o1+NS/5u+1u, o3=o2+NS/9u+1u, o4=o3+NS/17u+1u, LCAP=o4+NS/129u+1u;
    L.GA=GAb+(ulong)tg*LCAP; L.GB=GBb+(ulong)tg*LCAP; L.RK0=RKb+(ulong)tg*2ul*NS; L.RK1=L.RK0+NS;
    // P0 writes RK0 and emits into GB; the round loop swaps GA/GB first
    return Ctx{texts+(ulong)tg*NS, lens[tg], 0u, SAb+(ulong)tg*SS, L.RK1, L.RK0, L.RK1, L.GB, cnt, o1, o2, o3, o4, SGLb+(ulong)tg*NS, sgc};
}
inline void flushSingles(thread Ctx& c, uint tid, uint ntg){   // all reads of the round are done: finalize singletons
    uint ns=atomic_load_explicit(c.sgc,memory_order_relaxed);
    for(uint i=tid;i<ns;i+=ntg){ uint p=rki(c.SGL[i]); c.RKo[p]=c.RKw[p]; }
    threadgroup_barrier(mem_flags::mem_device|mem_flags::mem_threadgroup);
    if(tid==0u) atomic_store_explicit(c.sgc,0u,memory_order_relaxed);
}
// ---- P0: counting sort by a 12-bit key, bins in threadgroup memory
static void p0(thread Ctx& c, threadgroup atomic_uint* bins, threadgroup uint* tgs, uint tid, uint ntg, ushort sid, ushort lane, ushort nsg){
    const uint n=c.n;
    if(tid<5u) atomic_store_explicit(&c.cnt[tid],0u,memory_order_relaxed);
    if(tid==0u) atomic_store_explicit(c.sgc,0u,memory_order_relaxed);
    for(uint b=tid;b<NB;b+=ntg) atomic_store_explicit(&bins[b],0u,memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint p=tid;p<n;p+=ntg) atomic_fetch_add_explicit(&bins[k2(c.t,n,p)],1u,memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint chunk=(NB+ntg-1u)/ntg; uint c0=min(tid*chunk,NB), c1=min(c0+chunk,NB); uint s=0;
    for(uint b=c0;b<c1;b++) s+=atomic_load_explicit(&bins[b],memory_order_relaxed);
    uint incl=simd_prefix_inclusive_sum(s); if(lane==31) tgs[sid]=incl;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if(sid==0){ uint v=(lane<nsg)?tgs[lane]:0u; uint ex=simd_prefix_exclusive_sum(v); if(lane<nsg) tgs[lane]=ex; }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint base=tgs[sid]+incl-s;
    for(uint b=c0;b<c1;b++){ uint cv=atomic_load_explicit(&bins[b],memory_order_relaxed); atomic_store_explicit(&bins[b],base,memory_order_relaxed); base+=cv; }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint p=tid;p<n;p+=ntg){ uint slot=atomic_fetch_add_explicit(&bins[k2(c.t,n,p)],1u,memory_order_relaxed); c.SA[slot]=int(p); }
    threadgroup_barrier(mem_flags::mem_device|mem_flags::mem_threadgroup);
    for(uint j=tid;j<n;j+=ntg){ uint p=uint(c.SA[j]); uint b=k2(c.t,n,p);
        int st=b? int(atomic_load_explicit(&bins[b-1],memory_order_relaxed)):0; int en=int(atomic_load_explicit(&bins[b],memory_order_relaxed));
        setRank(c,p,st,en-st==1); if(int(j)==st && en-st>=2) emit(c,st,en-st); }
    threadgroup_barrier(mem_flags::mem_device|mem_flags::mem_threadgroup);
    flushSingles(c,tid,ntg);
}
// state[tg*8]: [0..4] group counts emitted by the last finished round (or P0), [5] rounds done,
// [6] 0 = in progress, 1 = sorted, 2 = refused (bad length or round cap); [7] unused.
#define SG_ARGS device const uchar* texts [[buffer(0)]], device const uint* lens [[buffer(1)]], \
                device int* SAb [[buffer(2)]], device int* RKb [[buffer(3)]], device uint* SGLb [[buffer(4)]], \
                device G* GAb [[buffer(5)]], device G* GBb [[buffer(6)]], device uint* state [[buffer(7)]], \
                constant uint& NS [[buffer(8)]], constant uint& SS [[buffer(9)]], constant uint& maxR [[buffer(10)]], \
                uint tg [[threadgroup_position_in_grid]], uint tid [[thread_index_in_threadgroup]], \
                uint ntg [[threads_per_threadgroup]], ushort sid [[simdgroup_index_in_threadgroup]], \
                ushort lane [[thread_index_in_simdgroup]], ushort nsg [[simdgroups_per_threadgroup]]
#define SG_MAXROUNDS 40u
kernel void sg_p0(SG_ARGS){
    threadgroup atomic_uint cnt[5]; threadgroup uint tgs[32]; threadgroup atomic_uint bins[NB]; threadgroup atomic_uint sgc;
    device uint* st = state + tg*8u;
    const uint n = lens[tg];
    if(n < 1u || n > NS || n > SS){ if(tid==0u){ st[5]=0u; st[6]=2u; } return; }
    Lay L; Ctx c=mkctx(texts,lens,SAb,RKb,SGLb,GAb,GBb,NS,SS,tg,cnt,&sgc,L);
    p0(c,bins,tgs,tid,ntg,sid,lane,nsg);
    if(tid<5u) st[tid]=atomic_load_explicit(&cnt[tid],memory_order_relaxed);
    if(tid==0u){ st[5]=0u; st[6]=0u; }
}
// at most maxR refinement rounds per dispatch (so every command buffer stays short); resumes from state[]
kernel void sg_rounds(SG_ARGS){
    threadgroup atomic_uint cnt[5]; threadgroup uint curCnt[5]; threadgroup atomic_uint sgc;
    device uint* st = state + tg*8u;
    if(st[6] != 0u) return;   // sorted or refused: uniform for the whole threadgroup
    Lay L; Ctx c=mkctx(texts,lens,SAb,RKb,SGLb,GAb,GBb,NS,SS,tg,cnt,&sgc,L);
    if(tid<5u) atomic_store_explicit(&cnt[tid],st[tid],memory_order_relaxed);
    if(tid==0u) atomic_store_explicit(&sgc,0u,memory_order_relaxed);
    uint rounds=st[5]; uint h = rounds==0u ? 0u : (H0<<(rounds-1u));
    device G* cur = (rounds&1u) ? L.GB : L.GA; device G* nxt = (rounds&1u) ? L.GA : L.GB;
    uint local=0;
    while(true){
        threadgroup_barrier(mem_flags::mem_device|mem_flags::mem_threadgroup);
        if(tid<5u){ curCnt[tid]=atomic_load_explicit(&c.cnt[tid],memory_order_relaxed); atomic_store_explicit(&c.cnt[tid],0u,memory_order_relaxed); }
        threadgroup_barrier(mem_flags::mem_threadgroup);
        uint cc[5]; uint tot=0; for(uint i=0;i<5;i++){ cc[i]=curCnt[i]; tot+=cc[i]; }
        if(tot==0u){ if(tid==0u){ st[5]=rounds; st[6]=1u; } return; }
        if(rounds>=SG_MAXROUNDS){ if(tid==0u){ st[5]=rounds; st[6]=2u; } return; }
        if(local>=maxR){ if(tid<5u) st[tid]=cc[tid]; if(tid==0u) st[5]=rounds; return; }
        local++; rounds++;
        device G* tmp=cur; cur=nxt; nxt=tmp;   // cur = groups emitted last round
        c.nxt=nxt; c.h=h;
        if(rounds&1u){ c.RKw=L.RK1; c.RKr=L.RK0; c.RKo=L.RK0; } else { c.RKw=L.RK0; c.RKr=L.RK1; c.RKo=L.RK1; }
        if(h>0u) phaseB<KD>(c,cur,cc,tid,ntg,sid,lane,nsg); else phaseB<K1>(c,cur,cc,tid,ntg,sid,lane,nsg);
        threadgroup_barrier(mem_flags::mem_device|mem_flags::mem_threadgroup);
        flushSingles(c,tid,ntg);
        h = (h==0u)? H0 : h*2u;
    }
}
