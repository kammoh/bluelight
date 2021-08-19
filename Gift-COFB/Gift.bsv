package Gift;

import InputLayer :: *;
import OutputLayer :: *;
import GiftCipher :: *;
import CryptoCore :: *;

typedef enum {
    Init,
    GetHeader,
    GetBdi,
    Tag
} State deriving(Bits, Eq);

(* synthesize *)
module mkGift(CryptoCoreIfc);
    Byte cipherPadByte = 8'h80;
    let cipher <- mkGiftCipher;
    let inLayer <- mkInputLayerNoExtraPad(cipherPadByte);
    let outLayer <- mkOutputLayer;
    let state <- mkReg(Init);

    Reg#(Bool) isKey <- mkRegU;
    Reg#(Bool) isCT <- mkRegU;
    Reg#(Bool) isPTCT <- mkRegU; // PT or CT
    Reg#(Bool) isNpub <- mkRegU;
    Reg#(Bool) isAD <- mkRegU;
    Reg#(Bool) isEoI <- mkRegU;
    Reg#(Bool) isFirstBlock <- mkRegU;
    Reg#(Bool) isLastBlock <- mkRegU;
    Reg#(Bool) haveKey <- mkReg(False);
    let set_isfirst <- mkPulseWire;
    let unset_isfirst <- mkPulseWire;

  // ==================================================== Rules =====================================================
    (* fire_when_enabled *)
    rule update_isfirst if(set_isfirst || unset_isfirst);
        if (set_isfirst)
            isFirstBlock <= True;
        else if (unset_isfirst)
            isFirstBlock <= False;
    endrule
    
    (* fire_when_enabled *)
    rule encipher if (haveKey);
        match {.inBlock, .valids} <- inLayer.get;
        let outBlock <- cipher.blockUp(inBlock, valids, Flags {ct:isCT, ptct:isPTCT, ad:isAD, npub:isNpub, first:isFirstBlock, last:isLastBlock, eoi: isEoI});
        if (isPTCT) outLayer.enq(outBlock, valids);
        unset_isfirst.send();
    endrule

    (* fire_when_enabled *)
    rule squeeze_tag_or_digest if (state == Tag);
        let out <- cipher.blockDown;
        outLayer.enq(out, replicate(True));
        state <= Init;
    endrule


  // ================================================== Interfaces ==================================================

    method Action init(Bool new_key, Bool decrypt, Bool hash) if (state == Init);
        state <= GetHeader;
        if (new_key) haveKey <= False;
    endmethod

    method Action key(w, is_last) if (!haveKey && state != Init && state != Tag);
        cipher.storeKey(w);
        if (is_last) haveKey <= True;
    endmethod

    method Action anticipate (Bool npub, Bool ad, Bool pt, Bool ct, Bool empty, Bool eoi) if (state == GetHeader);
        // only AD, CT, PT, HM can be empty
        let ptct = ct || pt;
        if (empty) begin
            if (ptct) state <= Tag;
            inLayer.put(unpack(zeroExtend(cipherPadByte)), True, False, 0, True);
        end else
            state <= GetBdi;

        set_isfirst.send();

        isLastBlock  <= empty;
        isNpub       <= npub;
        isCT         <= ct;
        isAD         <= ad;
        isPTCT       <= ptct;
        isEoI        <= eoi;
    endmethod
    
    method Action bdi(i) if (state == GetBdi);
        inLayer.put(unpack(pack(i.word)), i.last, i.last && !isNpub, i.padarg, False);
        isLastBlock <= i.last;
        if (i.last)
            state <= isPTCT ? Tag : GetHeader;
    endmethod


    interface FifoOut bdo;
        method deq = outLayer.deq;
        method first;
            return BdIO {word: outLayer.first, last: outLayer.isLast, padarg: 0};
        endmethod
        method notEmpty = outLayer.notEmpty;
    endinterface
  
endmodule : mkGift

endpackage : Gift
