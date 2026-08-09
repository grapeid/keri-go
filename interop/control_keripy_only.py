# Control: build the ENTIRE credential flow with keripy alone, feed it to the
# same harness, and see whether the issuance registers. If keripy's own message
# also fails to register, the harness is wrong, not keri-go.
import signal, sys, json
def bail(s,f): print("HUNG", flush=True); sys.exit(2)
signal.signal(signal.SIGALRM, bail); signal.alarm(150)

from keri.core import eventing, parsing, coring
from keri.core.signing import Signer
from keri.core.counting import Counter, Codens
from keri import kering
from keri.db import basing
from keri.vdr import eventing as vdr, viring

def sg(t): return Signer(raw=(t*32)[:32].encode(), code=coring.MtrDex.Ed25519_Seed)
D = lambda s: coring.Diger(ser=s.verfer.qb64.encode()).qb64

def signed(serder, signer):
    sig = signer.sign(ser=serder.raw, index=0)
    ctr = Counter(Codens.ControllerIdxSigs, count=1, gvrsn=kering.Vrsn_1_0)
    return bytes(serder.raw) + ctr.qb64b + sig.qb64b

def anchored(serder, sn, said):
    ctr = Counter(Codens.SealSourceCouples, count=1, gvrsn=kering.Vrsn_1_0)
    return bytes(serder.raw) + ctr.qb64b + coring.Seqner(sn=sn).qb64b + said.encode()

ia, ib = sg('t'), sg('u')
icp = eventing.incept(keys=[ia.verfer.qb64], ndigs=[D(ib)])
reg = vdr.incept(pre=icp.pre, nonce="0ADYvfKAeqRVAyc-Gu0Zc7SN")
ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1,
                         data=[dict(i=reg.pre, s="0", d=reg.said)])
from keri.vc import proving
cred = proving.credential(schema="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
                          issuer=icp.pre, status=reg.pre,
                          recipient="EHtQ1cqprq_XvngppRKybLalrmvpImmoPRojhfSNpgna",
                          data={"dt": "2024-01-01T00:00:00.000000+00:00",
                                "LEI": "254900OPPU84GM83MG36"})
iss = vdr.issue(vcdig=cred.said, regk=reg.pre, dt="2024-01-01T00:00:00.000000+00:00")
ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2,
                         data=[dict(i=cred.said, s="0", d=iss.said)])

with basing.openDB(name="ctl") as db, viring.openReger(name="ctl") as reger:
    kvy = eventing.Kevery(db=db, lax=True, local=True)
    tvy = vdr.Tevery(reger=reger, db=db, lax=True, local=True)
    parsing.Parser(kvy=kvy).parse(ims=bytearray(signed(icp, ia))); kvy.processEscrows()
    parsing.Parser(kvy=kvy).parse(ims=bytearray(signed(ixn1, ia))); kvy.processEscrows()
    parsing.Parser(kvy=kvy, tvy=tvy).parse(ims=bytearray(anchored(reg, 1, ixn1.said)))
    tvy.processEscrows()
    print("registry live:", reg.pre in tvy.tevers, flush=True)
    parsing.Parser(kvy=kvy).parse(ims=bytearray(signed(ixn2, ia))); kvy.processEscrows()
    parsing.Parser(kvy=kvy, tvy=tvy).parse(ims=bytearray(anchored(iss, 2, ixn2.said)))
    tvy.processEscrows()
    tev = tvy.tevers.get(reg.pre)
    print("KERIPY-ONLY issuance registers:", tev.vcState(cred.said) is not None, flush=True)
