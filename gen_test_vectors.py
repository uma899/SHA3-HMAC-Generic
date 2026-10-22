# see that different modes are also choosen
# Vectors generated need not be padded. Hence, use this file to test SHA3 module. 
import hmac, hashlib, random
random.seed(7)
algs={0:'sha3_224',1:'sha3_256',2:'sha3_384',3:'sha3_512'}
blk={0:144,1:136,2:104,3:72}
tests=[]
for m in range(4):
    b=blk[m]
    for kl in [0,1,3,4,5,b-1,b,b+1,b+3,2*b+5,300]:
        for ml in [0,1,4,7,b-1,b,b+1,2*b,2*b+3]:
            tests.append((m,kl,ml))
import sys
N=int(sys.argv[1]) if len(sys.argv)>1 else 24   # number of vectors (sim is slow; full matrix is ~400)
tests=[t for t in tests if t[1] in (0,1,5,blk[t[0]],blk[t[0]]+1) and t[2] in (0,1,7,blk[t[0]],blk[t[0]]+1)][:N]
with open('vec.txt','w') as f:
    f.write(f"{len(tests)}\n")
    for m,kl,ml in tests:
        k=bytes(random.randrange(256) for _ in range(kl)); msg=bytes(random.randrange(256) for _ in range(ml))
        d=hmac.new(k,msg,algs[m]).digest()
        f.write(f"{m} {kl} {ml} {len(d)}\n")
        f.write(" ".join(f"{x:02x}" for x in k)+(" " if kl else "")+"\n" if kl else "\n")
        f.write(" ".join(f"{x:02x}" for x in msg)+"\n" if ml else "\n")
        f.write(" ".join(f"{x:02x}" for x in d)+"\n")
