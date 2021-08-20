package Gift;

import GiftRound   :: *;
import InputLayer  :: *;
import OutputLayer :: *;
import GiftCipher  :: *;
import CryptoCore  :: *;

typedef enum {
    Init,
    GetHeader,
    GetBdi
} InState deriving(Bits, Eq);

typedef enum {
    OpIdle,
    OpAbsorb,
    OpPermute,
    OpGetTag
} OpState deriving(Bits, Eq);

typedef TDiv#(CipherRounds, UnrollFactor) PermCycles;

function KeyState restore_keystate(KeyState nextKS);
    KeyState swapped_ks = newVector;
    for (Integer i = 0; i < 8; i = i + 1)
        swapped_ks[i] = swapEndian(i % 2 == 0 ? rotateRight(nextKS[i], 4'b0) : nextKS[i]);
    return swapped_ks;
endfunction

// (* synthesize *)
module mkGift(CryptoCoreIfc);
    Byte cipherPadByte = 8'h80;
    let inLayer <- mkInputLayerNoExtraPad(cipherPadByte);
    let outLayer <- mkOutputLayer;
    let inState <- mkReg(Init);
    let opState <- mkReg(OpIdle);

    Reg#(Bool) isKey <- mkRegU;
    Reg#(Bool) isCT <- mkRegU;
    Reg#(Bool) isPTCT <- mkRegU; // PT or CT
    Reg#(Bool) isNpub <- mkRegU;
    Reg#(Bool) isAD <- mkRegU;
    Reg#(Bool) isEoI <- mkRegU;
    Reg#(Bool) isFirstADBlock <- mkRegU;
    Reg#(Bool) isLastBlock <- mkRegU;
    Reg#(Bool) nextGenTag <- mkRegU;
    let set_isfirst <- mkPulseWire;
    let unset_isfirst <- mkPulseWire;

    Reg#(GiftState) giftState <- mkRegU;
    Reg#(KeyState) keyState <- mkRegU;
    Reg#(RoundConstant) roundConstant <- mkRegU;
    let permutate <- mkReg(False);
    Reg#(HalfBlock) delta <- mkRegU;
    Reg#(Bit#(TLog#(PermCycles))) roundCounter <- mkRegU;
    Reg#(Bool) emptyM <- mkRegU;
    Reg#(Bool) emptyMsg <- mkRegU;
    Reg#(Bool) lastAdEmptyM <- mkRegU;

  // ==================================================== Rules =====================================================
    (* fire_when_enabled, no_implicit_conditions *)
    rule permutation if (opState == OpPermute);
        match {.nextGS, .nextKS, .nextRC} = giftRound(giftState, keyState, roundConstant);
        giftState <= nextGS;
        roundConstant <= nextRC;
        
        roundCounter <= roundCounter + 1;
        if (roundCounter == fromInteger(valueOf(PermCycles) - 1)) begin
            keyState <= restore_keystate(nextKS);
            opState <= nextGenTag ? OpGetTag : OpAbsorb;
        end else
            keyState <= nextKS;
    endrule
    
    (* fire_when_enabled, no_implicit_conditions *)
    rule update_isfirst if (set_isfirst || unset_isfirst);
        if (set_isfirst)
            isFirstADBlock <= True;
        else if (unset_isfirst)
            isFirstADBlock <= False;
    endrule
    
    (* fire_when_enabled *)
    rule absorb_in if (opState == OpAbsorb);
        match {.inBlock, .valids} <- inLayer.get;
        let y = giftStateToBlock(giftState);

        match {.x, .c} = pho(y, inBlock, valids, isCT);

        let offset = gen_offset(y, delta, isFirstADBlock, last(valids), isLastBlock);

        if (isNpub)
            giftState <= toGiftState(inBlock);
        else begin
            if (lastAdEmptyM)
                giftState <= toGiftState(x);
            else if (emptyMsg)
                giftState <= xor_topbar_block(giftStateToBlock(giftState), offset);
            else
                giftState <= xor_topbar_block(x, offset);
            delta <= offset;
        end
        roundConstant <= fromInteger(1);
        if (!lastAdEmptyM)
            opState <= OpPermute;
        nextGenTag <= isLastBlock && isPTCT;
        
        roundCounter <= 0;
        if (isPTCT) outLayer.enq(c, valids);
        unset_isfirst.send();
    endrule

    (* fire_when_enabled *)
    rule squeeze_tag if (opState == OpGetTag);
        let out = giftStateToBlock(giftState);
        outLayer.enq(out, replicate(True));
        opState <= OpIdle;
    endrule


  // ================================================== Interface ==================================================

    method Action init(Bool new_key, Bool decrypt, Bool hash) if (opState == OpIdle && inState == Init);
        inState <= GetHeader;
        if (!new_key) opState <= OpAbsorb;
    endmethod

    method Action key(w, is_last) if (opState == OpIdle && inState != Init);
        match {.hi, .lo} = split(w);
        let ks0 = shiftInAtN(keyState,  swapEndian(lo));
        keyState <= shiftInAtN(ks0,  swapEndian(hi));
        if (is_last) opState <= OpAbsorb;
    endmethod

    method Action anticipate (Bool npub, Bool ad, Bool pt, Bool ct, Bool empty, Bool eoi) if (inState == GetHeader);
        // only AD, CT, PT, HM can be empty
        let ptct = ct || pt;
        if (empty) begin
            inLayer.put(unpack(zeroExtend(cipherPadByte)), True, False, 0, True);
            if (ptct) inState <= Init;
        end else
            inState <= GetBdi;

        if (ad) set_isfirst.send();

        isLastBlock  <= empty;
        isNpub       <= npub;
        isCT         <= ct;
        isAD         <= ad;
        isPTCT       <= ptct;
        isEoI        <= eoi;

        if (npub)
            emptyM <= eoi; // set and unset, either new or reused key
        else if (ad && eoi)
            emptyM <= True; // don't unset if previously set

        emptyMsg <= emptyM && ptct;
        lastAdEmptyM <= ad && empty && (eoi || emptyM);

    endmethod
    
    method Action bdi(i) if (inState == GetBdi);
        inLayer.put(unpack(pack(i.word)), i.last, i.last && !isNpub, i.padarg, False);
        isLastBlock <= i.last;
        if (i.last) inState <= isPTCT ? Init : GetHeader;
        lastAdEmptyM <= isAD && i.last && emptyM;
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
