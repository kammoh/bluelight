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
    let inLayer <- mkInputLayer;
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
        let outBlock <- cipher.bin(inBlock, valids, isKey, isCT, isAD, isNpub, isHM, first, last_block);
        if (isPTCT) outLayer.enq(outBlock, valids);
        if (last_block) set_idle.send;
        first <= False;
    endrule

    (* fire_when_enabled *)
    rule rl_squeeze_tag_or_digest;
        let out <- cipher.bout;
        outLayer.enq(out, replicate(True));
    endrule 

  // ================================================== Interfaces ==================================================

    method Action process(SegmentType typ, Bool empty) if (inState == InIdle);
        // only AD, CT, PT, HM can be empty
        if (empty)
            inLayer.put(unpack(zeroExtend(1'b1)), True, False, 0, True);
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
            match tagged BdIO {word: .word, lot: .lot, padarg: .padarg} = i;
            inLayer.put(unpack(pack(word)), lot, lot && !isKey && !isNpub, padarg, False);
            last <= lot;
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
