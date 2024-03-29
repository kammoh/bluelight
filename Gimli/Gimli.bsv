package Gimli;

import InputLayer :: *;
import OutputLayer :: *;
import GimliCipher :: *;
import CryptoCore :: *;

typedef enum {
    InIdle, // waiting on process command
    InBusy  // recieve from bdi
} InputState deriving(Bits, Eq);

module mkGimli(CryptoCoreIfc);
    let cipher <- mkGimliCipher;
    Byte padByte = 8'b1;
    let inLayer <- mkInputLayer(padByte);
    let outLayer <- mkOutputLayer;
    let inState <- mkReg(InIdle);
    let set_busy <- mkPulseWire;
    let set_idle <- mkPulseWire;

    Reg#(Bool) isKey <- mkRegU;
    Reg#(Bool) isHM <- mkRegU;
    Reg#(Bool) isCT <- mkRegU;
    Reg#(Bool) isPTCT <- mkRegU; // PT or CT
    Reg#(Bool) isNpub <- mkRegU;
    Reg#(Bool) isAD <- mkRegU;
    Reg#(Bool) first <- mkRegU;
    Reg#(Bool) last <- mkRegU;

  // ==================================================== Rules =====================================================

    (* fire_when_enabled *)
    rule rl_change_state if (set_busy || set_idle);
        if (set_busy)
            inState <= InBusy;
        else if (set_idle)
            inState <= InIdle;
    endrule
    
    (* fire_when_enabled *)
    rule rl_encipher if (inState == InBusy);
        match {.inBlock, .valids} <- inLayer.get;
        let last_block = last && !inLayer.extraPad;

        let outBlock <- cipher.blockUp(inBlock, valids, Flags {key:isKey, ct:isCT, ad:isAD, npub:isNpub, hash:isHM, first:first, last:last_block});
        if (isPTCT) outLayer.enq(outBlock, valids);
        if (last_block) set_idle.send;
        first <= False;
    endrule

    (* fire_when_enabled *)
    rule rl_squeeze_tag_or_digest;
        let out <- cipher.blockDown;
        outLayer.enq(out, replicate(True));
    endrule 

  // ================================================== Interfaces ==================================================

    method Action init(OpCode op) if (inState == InIdle);
        cipher.init(op);
    endmethod

    method Action process(SegmentType typ, Bool empty, Bool eoi) if (inState == InIdle);
        // only AD, CT, PT, HM can be empty
        if (empty)
            inLayer.put(unpack(zeroExtend(padByte)), True, False, 0, True);
        set_busy.send;
        first  <= True;
        last   <= empty;
        isKey  <= typ == Key;
        isNpub <= typ == Npub;
        isHM   <= typ == HashMessage;
        isCT   <= typ == Ciphertext;
        isAD   <= typ == AD;
        isPTCT <= typ == Ciphertext || typ == Plaintext;
    endmethod
    
    interface FifoIn bdi;
        method Action enq(i) if (inState == InBusy);
            inLayer.put(unpack(pack(i.word)), i.lot, i.lot && !isKey && !isNpub, i.padarg, False);
            last <= i.lot;
        endmethod
    endinterface

    interface FifoOut bdo;
        method deq = outLayer.deq;
        method first;
            return BdIO {word: outLayer.first, lot: outLayer.isLast, padarg: 0};
        endmethod
        method notEmpty = outLayer.notEmpty;
    endinterface
  
endmodule : mkGimli

endpackage : Gimli
