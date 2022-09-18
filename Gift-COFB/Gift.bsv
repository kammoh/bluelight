package Gift;

import GiftRound   :: *;
import InputLayer  :: *;
import OutputLayer :: *;
import GiftCipher  :: *;

typedef enum {
    Init,
    GetBdi,
    PadFullWord
} InState deriving(Bits, Eq);

typedef enum {
    OpIdle,
    OpAbsorb,
    OpPermute,
    OpGetTag
} OpState deriving(Bits, Eq);

typedef TDiv#(CipherRounds, UnrollFactor) PermCycles;

// (* synthesize *)
module mkGift(CryptoCoreIfc);
    Byte cipherPadByte = 8'h80;
    let inLayer                                <- mkInputLayerNoExtraPad(cipherPadByte);
    let outLayer                               <- mkOutputLayer;

    let inState                                <- mkReg(Init);
    let opState                                <- mkReg(OpIdle);
    Reg#(Bool) isKey                           <- mkRegU;
    Reg#(Bool) isCT                            <- mkRegU;
    Reg#(Bool) isPTCT                          <- mkRegU;
    Reg#(Bool) isNpub                          <- mkRegU;
    Reg#(Bool) isAD                            <- mkRegU;
    Reg#(Bool) isEoI                           <- mkRegU;
    Reg#(Bool) isFirstADBlock                  <- mkRegU;
    Reg#(Bool) isLastBlock                     <- mkRegU;
    Reg#(Bool) nextGenTag                      <- mkRegU;
    Reg#(GiftState) giftState                  <- mkRegU;
    Reg#(KeyState) keyState                    <- mkRegU;
    Reg#(RoundConstant) roundConstant          <- mkRegU;
    Reg#(HalfBlock) delta                      <- mkRegU;
    Reg#(Bit#(TLog#(PermCycles))) roundCounter <- mkRegU;
    Reg#(Bool) emptyM                          <- mkRegU;
    Reg#(Bool) emptyMsg                        <- mkRegU;
    Reg#(Bool) lastAdEmptyM                    <- mkRegU;
    let set_isfirst                            <- mkPulseWire;
    let unset_isfirst                          <- mkPulseWire;

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

    method Action initOp (OpFlags op) if (opState == OpIdle && inState == Init);
        inState <= GetBdi;
        if (!op.new_key) opState <= OpAbsorb;
    endmethod

    method Action key (w, is_last) if (opState == OpIdle && inState != Init);
        match {.hi, .lo} = split(w);
        let ks0 = shiftInAtN(keyState,  swapEndian(lo));
        keyState <= shiftInAtN(ks0,  swapEndian(hi));
        if (is_last) opState <= OpAbsorb;
    endmethod

    method Action anticipate (HeaderFlags flags) if (inState == GetHeader);
        if (flags.empty) begin
            inLayer.put(unpack(zeroExtend(cipherPadByte)), True, False, 0, True);
            if (flags.ptct) inState <= Init;
        end else
            inState <= GetBdi;

        if (flags.ad) set_isfirst.send();

        isLastBlock  <= flags.empty;
        isNpub       <= flags.npub;
        isCT         <= flags.ct;
        isAD         <= flags.ad;
        isPTCT       <= flags.ptct;
        isEoI        <= flags.eoi;

        if (flags.npub)
            emptyM <= flags.eoi; // set and unset, either new or reused key
        else if (flags.ad && flags.eoi)
            emptyM <= True; // don't unset if previously set

        emptyMsg     <= emptyM && flags.ptct;
        lastAdEmptyM <= flags.ad && flags.empty && (flags.eoi || emptyM);
    endmethod
    
    method Action bdi(i) if (inState == GetBdi);
        inLayer.put(unpack(pack(i.word)), i.last, i.last && !isNpub, i.padarg, False);
        if (i.last && isPTCT) inState <=  Init;
        isLastBlock  <= i.last;
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
