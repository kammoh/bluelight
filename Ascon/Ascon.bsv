package Ascon;

import Vector :: *;
import BluelightUtils :: *;
import InputLayer :: *;
import OutputLayer :: *;
import CryptoCore :: *;
import AsconCipher :: *;
import LwcApi :: *;

typedef enum {
    InIdle, // waiting on process command
    GetKey, // waiting on process command
    GetBdi  // receive from bdi
} InputState deriving(Bits, Eq);

module mkAscon(CryptoCoreIfc);
    let cipher <- mkAsconCipher;
    Byte padByte = 8'h80;
    let inLayer <- mkInputLayer(padByte);
    let outLayer <- mkOutputLayer;
    let inState <- mkReg(InIdle);
    // let change_state <- mkPulseWire;

    Reg#(Bool) isKey <- mkRegU;
    Reg#(Bool) isHM <- mkRegU;
    Reg#(Bool) isCT <- mkRegU;
    Reg#(Bool) isPTCT <- mkRegU; // PT or CT
    Reg#(Bool) isNpub <- mkRegU;
    Reg#(Bool) isAD <- mkRegU;
    Reg#(Bool) first <- mkRegU;
    Reg#(Bool) last <- mkRegU;

  // ==================================================== Rules =====================================================

    // (* fire_when_enabled *)
    // rule rl_change_state if (change_state);
    //     if (inState == )
    //         inState <= GetBdi;
    //     else if (inState == InIdle)
    //         inState <= InIdle;
    // endrule
    
    (* fire_when_enabled *)
    rule rl_encipher if (inState == GetBdi);
        match {.inBlock, .valids} <- inLayer.get;
        let last_block = last && !inLayer.extraPad;

        let outBlock <- cipher.blockUp(inBlock, valids, Flags {key:isKey, npub:isNpub, ad:isAD, ptct:isPTCT, ct:isCT, hash:isHM, first:first, last:last_block});
        
        if (isPTCT)
            outLayer.enq(outBlock, valids);
        if (last_block)
            inState <= InIdle;
        first <= False;
    endrule

    (* fire_when_enabled *)
    rule rl_squeeze_tag_or_digest;
        let out <- cipher.blockDown;
        outLayer.enq(out, replicate(True));
    endrule 

  // ================================================== Interfaces ==================================================

    method Action initOp(OpFlags op) if (inState == InIdle);
        cipher.init(op);
        if (op.new_key)
            inState <= GetKey;
    endmethod

    // meta-data, header
    // after fire, anticipate bdi words of this type, unless flags.empty == True.
    method Action anticipate (HeaderFlags flags) if (inState == InIdle);
        // only AD, CT, PT, HM can be empty
        if (flags.empty) inLayer.put(unpack(zeroExtend(padByte)), True, False, 0, True);
        inState <= GetBdi;
        first  <= True;
        last   <= flags.eoi;
        isKey  <= False;
        isNpub <= flags.npub;
        isHM   <= flags.hm;
        isCT   <= flags.ct;
        isAD   <= flags.ad;
        isPTCT <= flags.ptct;
    endmethod

    // Receive a word of the key
    method Action key (CoreWord w, Bool lst)  if (inState == GetKey);
        inLayer.put(unpack(pack(w)), lst, False, 0, False);
        last <= lst;
        isKey <= True;
        inState <= GetBdi;
    endmethod

    // Receive a word of Public Nonce, Associated Data, Plaintext, Ciphertext, or Hash Message
    // data:        data word
    // valid_bytes: bit array indicating which bytes in `data` are valid
    // last:        this is the last word of the type
    method Action bdi (CoreWord data, ValidBytes#(CoreWord) valid_bytes, Bool last, HeaderFlags flags) if (inState == GetBdi);
        inLayer.put(unpack(pack(data)), last, last && !flags.npub, i.padarg, False);
        last <= i.last;
    endmethod

    interface FifoOut bdo;
        method deq = outLayer.deq;
        method first;
            return BdIO {word: outLayer.first, last: outLayer.isLast, padarg: 0};
        endmethod
        method notEmpty = outLayer.notEmpty;
    endinterface
  
endmodule : mkAscon

endpackage : Ascon
