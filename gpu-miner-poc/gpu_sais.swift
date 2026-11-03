import Metal
import Foundation
setbuf(stdout, nil)

// GPU stage-3c-opt: LINEAR SA-IS (sais_32) on GPU, flattened recursion (separate buffer per level,
// explicit down/up stack, depth<=10). Reads the validated pre-SAIS data (gpu_loop_<i>.bin), builds
// the suffix array, final SHA256, outputs 32-byte hash -> compared to AstroBWTv3 (cmd/_saisvalidate).
// Faithful port of astrobwt/astrobwtv3/sais2.go sais_32 + helpers (int32 variant covers all levels).

let msl = """
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
static void sha256_block(thread uint* H, thread const uchar* blk){
    uint w[64]; for(uint i=0;i<16;i++) w[i]=(uint(blk[i*4])<<24)|(uint(blk[i*4+1])<<16)|(uint(blk[i*4+2])<<8)|uint(blk[i*4+3]);
    for(uint i=16;i<64;i++){uint s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);uint s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
    uint a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(uint i=0;i<64;i++){uint S1=rotr(e,6)^rotr(e,11)^rotr(e,25);uint ch=(e&f)^((~e)&g);uint t1=h+S1+ch+KC[i]+w[i];uint S0=rotr(a,2)^rotr(a,13)^rotr(a,22);uint mj=(a&b)^(a&c)^(b&c);uint t2=S0+mj;h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}
static void sha256_sa(device int* sa, uint n, thread uchar* out){
    uint H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    ulong totalBytes=(ulong)n*4; uchar blk[64]; uint bl=0;
    for(uint i=0;i<n;i++){ uint v=uint(sa[i]); for(uint b=0;b<4;b++){ blk[bl++]=uchar(v>>(8*b)); if(bl==64){ sha256_block(H,blk); bl=0; } } }
    blk[bl++]=0x80; if(bl>56){ while(bl<64) blk[bl++]=0; sha256_block(H,blk); bl=0; }
    while(bl<56) blk[bl++]=0;
    ulong bits=totalBytes*8; for(uint i=0;i<8;i++) blk[56+i]=uchar(bits>>(56-8*i));
    sha256_block(H,blk);
    for(uint i=0;i<8;i++){out[i*4]=uchar(H[i]>>24);out[i*4+1]=uchar(H[i]>>16);out[i*4+2]=uchar(H[i]>>8);out[i*4+3]=uchar(H[i]);}
}

// ---- SA-IS helpers (device pointers; text/sa are int32; freq,bucket sized textMax) ----
static void compute_freq(device int* text, uint n, device int* freq, uint tmax){
    for(uint c=0;c<tmax;c++) freq[c]=0;
    for(uint i=0;i<n;i++) freq[text[i]]++;
}
static void bucketMax(device int* text, uint n, device int* freq, device int* bucket, uint tmax){
    compute_freq(text,n,freq,tmax); int total=0; for(uint c=0;c<tmax;c++){ total+=freq[c]; bucket[c]=total; }
}
static void bucketMin(device int* text, uint n, device int* freq, device int* bucket, uint tmax){
    compute_freq(text,n,freq,tmax); int total=0; for(uint c=0;c<tmax;c++){ bucket[c]=total; total+=freq[c]; }
}
static int placeLMS(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    bucketMax(text,n,freq,bucket,tmax);
    int numLMS=0; int lastB=-1; int c0=0,c1=0; bool isS=false;
    for(int i=int(n)-1;i>=0;i--){ c1=c0; c0=text[i];
        if(c0<c1) isS=true;
        else if(c0>c1 && isS){ isS=false; int b=bucket[c1]-1; bucket[c1]=b; sa[b]=i+1; lastB=b; numLMS++; }
    }
    if(numLMS>1) sa[lastB]=0;
    return numLMS;
}
static void induceSubL(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    bucketMin(text,n,freq,bucket,tmax);
    int k=int(n)-1; int c0=text[k-1], c1=text[k]; if(c0<c1) k=-k;
    int cB=c1; int b=bucket[cB]; sa[b]=k; b++;
    for(uint i=0;i<n;i++){ int j=sa[i];
        if(j==0) continue;
        if(j<0){ sa[i]=-j; continue; }
        sa[i]=0;
        int kk=j-1; int cc0=text[kk-1], cc1=text[kk]; if(cc0<cc1) kk=-kk;
        if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; }
        sa[b]=kk; b++;
    }
}
static void induceSubS(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    bucketMax(text,n,freq,bucket,tmax);
    int cB=0; int b=bucket[cB]; int top=int(n);
    for(int i=int(n)-1;i>=0;i--){ int j=sa[i];
        if(j==0) continue;
        sa[i]=0;
        if(j<0){ top--; sa[top]=-j; continue; }
        int kk=j-1; int cc1=text[kk], cc0=text[kk-1]; if(cc0>cc1) kk=-kk;
        if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; }
        b--; sa[b]=kk;
    }
}
static void lengthLMS(device int* text, uint n, device int* sa, int numLMS){
    int end=0; int c0=0,c1=0; bool isS=false;
    for(int i=int(n)-1;i>=0;i--){ c1=c0; c0=text[i];
        if(c0<c1) isS=true;
        else if(c0>c1 && isS){ isS=false; int j=i+1; int code=(end==0)?0:(end-j); sa[j>>1]=code; end=j+1; }
    }
}
static int assignID(device int* text, uint n, device int* sa, int numLMS){
    int id=0; int lastLen=-1; int lastPos=0;
    for(int t=int(n)-numLMS; t<int(n); t++){ int j=sa[t];
        int nn=sa[j/2]; bool isNew=false;
        if(nn!=lastLen) isNew=true;
        else if(uint(nn)>=n) isNew=false; // encoded full text, match
        else { isNew=false; for(int i=0;i<nn;i++){ if(text[j+i]!=text[lastPos+i]){ isNew=true; break; } } }
        if(isNew){ id++; lastPos=j; lastLen=nn; }
        sa[j/2]=id;
    }
    return id;
}
static void induceL(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    bucketMin(text,n,freq,bucket,tmax);
    int k=int(n)-1; int c0=text[k-1], c1=text[k]; if(c0<c1) k=-k;
    int cB=c1; int b=bucket[cB]; sa[b]=k; b++;
    for(uint i=0;i<n;i++){ int j=sa[i]; if(j<=0) continue;
        int kk=j-1; int cc1=text[kk]; if(kk>0){ int cc0=text[kk-1]; if(cc0<cc1) kk=-kk; }
        if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; }
        sa[b]=kk; b++;
    }
}
static void induceS(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax){
    bucketMax(text,n,freq,bucket,tmax);
    int cB=0; int b=bucket[cB];
    for(int i=int(n)-1;i>=0;i--){ int j=sa[i]; if(j>=0) continue;
        j=-j; sa[i]=j;
        int kk=j-1; int cc1=text[kk]; if(kk>0){ int cc0=text[kk-1]; if(cc0<=cc1) kk=-kk; }
        if(cB!=cc1){ bucket[cB]=b; cB=cc1; b=bucket[cB]; }
        b--; sa[b]=kk;
    }
}
static void expandLMS(device int* text, uint n, device int* sa, device int* freq, device int* bucket, uint tmax, int numLMS){
    bucketMax(text,n,freq,bucket,tmax);
    int x=numLMS-1; int saX=sa[x]; int c=text[saX]; int b=bucket[c]-1; bucket[c]=b;
    for(int i=int(n)-1;i>=0;i--){
        if(i!=b){ sa[i]=0; continue; }
        sa[i]=saX;
        if(x>0){ x--; saX=sa[x]; c=text[saX]; b=bucket[c]-1; bucket[c]=b; }
    }
}
// build lms_pos[k] = text position of k-th LMS substring in TEXT order, into dst[0..numLMS)
static void lmsPositions(device int* text, uint n, device int* dst, int numLMS){
    int w=0; int c0=0,c1=0; bool isS=false; // forward via reverse then reverse-fill? Go scans backward filling from right
    // Go unmap scans backward, filling unmap[j--] = i+1 (so unmap ends in text order left->right). Replicate:
    int j=numLMS;
    for(int i=int(n)-1;i>=0;i--){ c1=c0; c0=text[i];
        if(c0<c1) isS=true;
        else if(c0>c1 && isS){ isS=false; j--; dst[j]=i+1; }
    }
}

// full SA-IS via flattened recursion. textPool/saPool: 2n int32 each. freq/bucket: tmax scratch. stack depth<=12.
kernel void sais(device int* textPool [[buffer(0)]], device int* saPool [[buffer(1)]], device int* freq [[buffer(2)]], device int* bucket [[buffer(3)]],
                 device const int* dlens [[buffer(4)]], constant uint& poolstride [[buffer(5)]], constant uint& bstride [[buffer(6)]],
                 device uchar* outs [[buffer(7)]], uint gid [[thread_position_in_grid]]){
    device int* TP = textPool + (ulong)gid*poolstride;
    device int* SP = saPool + (ulong)gid*poolstride;
    device int* FQ = freq + (ulong)gid*bstride;
    device int* BK = bucket + (ulong)gid*bstride;
    uint n0 = uint(dlens[gid]);

    // down-pass stack
    uint tbase[16]; uint sbase[16]; uint flen[16]; uint ftmax[16]; int fnum[16]; int fmax[16]; bool frec[16];
    int depth=0;
    uint curTbase=0, curSbase=0, curN=n0, curTmax=256;
    uint nextTbase=n0, nextSbase=n0; // level>0 buffers packed after level0
    while(true){
        device int* text=TP+curTbase; device int* sa=SP+curSbase;
        for(uint i=0;i<curN;i++) sa[i]=0;
        int numLMS = placeLMS(text,curN,sa,FQ,BK,curTmax);
        int maxID=0; bool rec=false;
        if(numLMS>1){
            induceSubL(text,curN,sa,FQ,BK,curTmax);
            induceSubS(text,curN,sa,FQ,BK,curTmax);
            lengthLMS(text,curN,sa,numLMS);
            maxID=assignID(text,curN,sa,numLMS);
            rec = (maxID<numLMS);
        }
        tbase[depth]=curTbase; sbase[depth]=curSbase; flen[depth]=curN; ftmax[depth]=curTmax; fnum[depth]=numLMS; fmax[depth]=maxID; frec[depth]=rec;
        depth++;
        if(rec){
            // build reduced text (ID-1 in text order) into TP[nextTbase..]
            device int* rt=TP+nextTbase; int w=0;
            for(uint i=0;i<=curN/2;i++){ int v=sa[i]; if(v>0){ rt[w]=v-1; w++; } }
            curTbase=nextTbase; curSbase=nextSbase; nextTbase+=uint(numLMS); nextSbase+=uint(numLMS);
            curN=uint(numLMS); curTmax=uint(maxID);
            continue;
        }
        break;
    }
    // up-pass
    for(int d=depth-1; d>=0; d--){
        device int* text=TP+tbase[d]; device int* sa=SP+sbase[d]; uint N=flen[d]; uint TM=ftmax[d]; int numLMS=fnum[d];
        if(numLMS>1){
            if(frec[d]){
                // child sa (level d+1) is at SP+sbase[d+1]; convert reduced positions -> text positions
                device int* childSa=SP+sbase[d+1];
                // lms positions of THIS level into sa top region [N-numLMS..N)
                device int* unmap=sa+(N-uint(numLMS));
                lmsPositions(text,N,unmap,numLMS);
                for(int i=0;i<numLMS;i++) sa[i]=unmap[childSa[i]];
            } else {
                // sa[:numLMS] = sorted LMS starts (currently at sa[N-numLMS..N))
                for(int i=0;i<numLMS;i++) sa[i]=sa[int(N)-numLMS+i];
            }
            expandLMS(text,N,sa,FQ,BK,TM,numLMS);
        }
        induceL(text,N,sa,FQ,BK,TM);
        induceS(text,N,sa,FQ,BK,TM);
    }
    uchar out[32]; sha256_sa(SP+0, n0, out); // level-0 sa = final suffix array
    device uchar* o = outs + (ulong)gid*32; for(uint i=0;i<32;i++) o[i]=out[i];
}
"""

guard let dev = MTLCreateSystemDefaultDevice() else { exit(1) }
let q = dev.makeCommandQueue()!
let lib: MTLLibrary
do { lib = try dev.makeLibrary(source: msl, options: nil) } catch { print("MSL ERR:\n\(error)"); exit(2) }
let pso = try dev.makeComputePipelineState(function: lib.makeFunction(name:"sais")!)
print("sais kernel compiled OK.")

let POOL = 2*71200, BSTR = 9200
let inputs = ["a","ab","abc","abcd","abcde","abcdef","abcdefg","abcdefgh","abcdefghi","abcdefghij","48x00"]
for (idx,label) in inputs.enumerated() {
    guard let raw = try? Data(contentsOf: URL(fileURLWithPath:"gpu_loop_\(idx).bin")) else { print("missing gpu_loop_\(idx).bin"); continue }
    let dlen = raw.withUnsafeBytes { $0.load(as: UInt32.self) }
    let data = raw.subdata(in: 4..<(4+Int(dlen)))
    // promote bytes to int32 into textPool[0..dlen)
    let TP = dev.makeBuffer(length: POOL*4, options:.storageModePrivate)!
    let SP = dev.makeBuffer(length: POOL*4, options:.storageModePrivate)!
    let FQ = dev.makeBuffer(length: BSTR*4, options:.storageModePrivate)!
    let BK = dev.makeBuffer(length: BSTR*4, options:.storageModePrivate)!
    let dl = dev.makeBuffer(length: 4, options:.storageModeShared)!
    dl.contents().storeBytes(of: dlen, as: UInt32.self)
    // init textPool[0..dlen) via a tiny promote kernel is overkill; use a shared staging buffer
    let stage = dev.makeBuffer(length: Int(dlen)*4, options:.storageModeShared)!
    let sp = stage.contents().bindMemory(to: Int32.self, capacity: Int(dlen))
    data.withUnsafeBytes { (bp: UnsafeRawBufferPointer) in for i in 0..<Int(dlen) { sp[i]=Int32(bp[i]) } }
    let ob = dev.makeBuffer(length:32, options:.storageModeShared)!
    var ps=UInt32(POOL); var bs=UInt32(BSTR)
    // blit stage -> TP[0..dlen)
    let bcb=q.makeCommandBuffer()!; let bl=bcb.makeBlitCommandEncoder()!; bl.copy(from:stage,sourceOffset:0,to:TP,destinationOffset:0,size:Int(dlen)*4); bl.endEncoding(); bcb.commit(); bcb.waitUntilCompleted()
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(TP,offset:0,index:0); e.setBuffer(SP,offset:0,index:1); e.setBuffer(FQ,offset:0,index:2); e.setBuffer(BK,offset:0,index:3)
    e.setBuffer(dl,offset:0,index:4); e.setBytes(&ps,length:4,index:5); e.setBytes(&bs,length:4,index:6); e.setBuffer(ob,offset:0,index:7)
    e.dispatchThreads(MTLSize(width:1,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:1,height:1,depth:1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    let ok = cb.status == .completed && cb.error == nil
    let p=ob.contents().bindMemory(to:UInt8.self,capacity:32); var hex=""; for i in 0..<32 { hex+=String(format:"%02x",p[i]) }
    try? Data(bytes:ob.contents(),count:32).write(to: URL(fileURLWithPath:"gpu_sais_\(idx).bin"))
    print(String(format:"%-12@ %@ ok=%@", label as NSString, hex as NSString, ok ? "Y":"N"))
}
print("wrote gpu_sais_*.bin — run: go run ./cmd/_saisvalidate")

// ---- throughput: N threads each running SA-IS on a ~68KB pre-SAIS buffer ----
print("\nGPU SA-IS throughput (N threads, one suffix array each, ~68KB):")
guard let raw0 = try? Data(contentsOf: URL(fileURLWithPath:"gpu_loop_6.bin")) else { exit(0) }
let dlen0 = raw0.withUnsafeBytes { $0.load(as: UInt32.self) }
let data0 = raw0.subdata(in: 4..<(4+Int(dlen0)))
for N in [64, 256, 1024, 4096, 8192] {
    let gb = Double(N) * Double(POOL*4*2 + BSTR*4*2) / 1e9
    guard let TP=dev.makeBuffer(length:POOL*4*N,options:.storageModePrivate),
          let SP=dev.makeBuffer(length:POOL*4*N,options:.storageModePrivate),
          let FQ=dev.makeBuffer(length:BSTR*4*N,options:.storageModePrivate),
          let BK=dev.makeBuffer(length:BSTR*4*N,options:.storageModePrivate),
          let dl=dev.makeBuffer(length:4*N,options:.storageModeShared),
          let ob=dev.makeBuffer(length:32*N,options:.storageModeShared),
          let stage=dev.makeBuffer(length:Int(dlen0)*4,options:.storageModeShared) else { print(String(format:"%7d alloc-fail %.1fGB",N,gb)); break }
    let sp=stage.contents().bindMemory(to:Int32.self,capacity:Int(dlen0))
    data0.withUnsafeBytes { (bp:UnsafeRawBufferPointer) in for i in 0..<Int(dlen0) { sp[i]=Int32(bp[i]) } }
    let dlp=dl.contents().bindMemory(to:UInt32.self,capacity:N); for i in 0..<N { dlp[i]=dlen0 }
    // blit stage into each thread's textPool[0]
    let bcb=q.makeCommandBuffer()!; let ble=bcb.makeBlitCommandEncoder()!
    for i in 0..<N { ble.copy(from:stage,sourceOffset:0,to:TP,destinationOffset:i*POOL*4,size:Int(dlen0)*4) }
    ble.endEncoding(); bcb.commit(); bcb.waitUntilCompleted()
    var ps=UInt32(POOL); var bs=UInt32(BSTR)
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(TP,offset:0,index:0); e.setBuffer(SP,offset:0,index:1); e.setBuffer(FQ,offset:0,index:2); e.setBuffer(BK,offset:0,index:3)
    e.setBuffer(dl,offset:0,index:4); e.setBytes(&ps,length:4,index:5); e.setBytes(&bs,length:4,index:6); e.setBuffer(ob,offset:0,index:7)
    e.dispatchThreads(MTLSize(width:N,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(N,32),height:1,depth:1))
    e.endEncoding(); let t0=Date(); cb.commit(); cb.waitUntilCompleted(); let dt=Date().timeIntervalSince(t0)
    let ok = cb.status == .completed && cb.error == nil
    print(String(format:"%7d threads  %.2fs  %8.1f SA/s  scratch=%.1fGB  ok=%@", N, dt, Double(N)/dt, gb, ok ? "Y":"KILL"))
    if !ok { break }
}
