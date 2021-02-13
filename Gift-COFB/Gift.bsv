package Gift;

import InputLayer :: *;
import OutputLayer :: *;
import GiftCipher :: *;
import CryptoCore :: *;

typedef enum {
    InIdle, // waiting on process command
    InBusy  // recieve from bdi
} InputState deriving(Bits, Eq);

module mkGift(CryptoCoreIfc);
    Byte cipherPadByte = 8'h80;
    let cipher <- mkGiftCipher;
    let inLayer <- mkInputLayerNoExtraPad(cipherPadByte);
    let outLayer <- mkOutputLayer;
    let inState <- mkReg(InIdle);
    let set_busy <- mkPulseWire;
    let set_idle <- mkPulseWire;

    Reg#(Bool) isKey <- mkRegU;
    Reg#(Bool) isCT <- mkRegU;
    Reg#(Bool) isPTCT <- mkRegU; // PT or CT
    Reg#(Bool) isNpub <- mkRegU;
    Reg#(Bool) isAD <- mkRegU;
    Reg#(Bool) isEoI <- mkRegU;
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

        let outBlock <- cipher.blockUp(inBlock, valids, Flags {key:isKey, ct:isCT, ptct:isPTCT, ad:isAD, npub:isNpub, first:first, last:last, eoi: isEoI});
        if (isPTCT) outLayer.enq(outBlock, valids);
        if (last) set_idle.send;
        first <= False;
    endrule

    (* fire_when_enabled *)
    rule rl_squeeze_tag_or_digest;
        let out <- cipher.blockDown;
        outLayer.enq(out, replicate(True));
    endrule 

  // ================================================== Interfaces ==================================================

    method Action init(OpCode op);
    endmethod

    method Action process(SegmentType typ, Bool empty, Bool eoi) if (inState == InIdle);
        // only AD, CT, PT, HM can be empty
        if (empty)
            inLayer.put(unpack(zeroExtend(cipherPadByte)), True, False, 0, True);
        set_busy.send;
        first  <= True;
        last   <= empty;
        isKey  <= typ == Key;
        isNpub <= typ == Npub;
        isCT   <= typ == Ciphertext;
        isAD   <= typ == AD;
        isPTCT <= typ == Ciphertext || typ == Plaintext;
        isEoI  <= eoi;
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
  
endmodule : mkGift

endpackage : Gift
