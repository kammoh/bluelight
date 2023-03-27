package Ascon;

import Vector :: *;
import Probe :: * ;

import LwcApi :: *;
import BluelightUtils :: *;
import InputLayer :: *;
import OutputLayer :: *;
import AsconCipher :: *;
import CryptoCore :: *;

// typedef enum {
//     InIdle, // waiting on process command
//     GetKey, // waiting on process command
//     GetBdi  // receive from bdi
// } InputState deriving(Bits, Eq);

module mkAscon(CryptoCoreIfc#(w__)) provisos (NumAlias#(w__, 32));
    let cipher <- mkAsconCipher;
    Byte padByte = 8'h80;
    let inLayer <- mkInputLayer(padByte);
    let outLayer <- mkOutputLayer;
    // let inState <- mkReg(InIdle);
    let bdiFlags <- mkRegU; // LwcFlags
    
    Reg#(Bool) isLast <- mkRegU;

    (* doc = "the output of inputLayer" *)
    Probe#(InputBlock#(8)) inBlock_probe <- mkProbe();

  // ==================================================== Rules =====================================================


    (* fire_when_enabled *)
    rule rl_get_inlayer;
        let inBlock <- inLayer.get;
        inBlock_probe <= inBlock;
        let outBlock <- cipher.absorb(inBlock.data, inBlock.valid_bytes, inBlock.last, bdiFlags);
        if (bdiFlags.ptct)
            outLayer.enq(outBlock, inBlock.valid_bytes);
    endrule

    (* fire_when_enabled *)
    rule rl_squeeze_tag_or_digest;
        let out <- cipher.squeeze;
        outLayer.enq(out, replicate(True));
    endrule 

  // ================================================== Interfaces ==================================================

    method Action start(OpFlags op);
        cipher.start(op);
    endmethod

    // Receive a word of the key
    method Action loadKey (Bit#(w__) data, Bool last);
        cipher.loadKey(data, last);
    endmethod

    // Receive a word of Public Nonce, Associated Data, Plaintext, Ciphertext, or Hash Message
    // data:        data word
    // valid_bytes: bit array indicating which bytes in `data` are valid
    // last:        this is the last word of the type
    method Action loadData (Bit#(w__) data, Bit#(TDiv#(w__, 8)) valid_bytes, Bit#(TDiv#(w__, 8)) pad_loc, Bool last, HeaderFlags flags);
        inLayer.put(unpack(pack(data)), valid_bytes, last && !flags.npub);
        bdiFlags <= flags;
        isLast <= last;
    endmethod

    interface FifoOut data_out;
        method deq = outLayer.deq;
        method first;
            return WithLast {
                data: clear_invalid_bytes_cond(outLayer.first, outLayer.first_valid_bytes, outLayer.isLast),
                last: outLayer.isLast
            };
        endmethod
        method notEmpty = outLayer.notEmpty;
    endinterface
  
endmodule : mkAscon

endpackage : Ascon
