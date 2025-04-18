package Ascon;

import Vector :: *;
import Probe :: * ;

import LwcApi :: *;
import BluelightUtils :: *;
import InputLayer :: *;
import OutputLayer :: *;
import AsconCipher :: *;
import CryptoCore :: *;

`ifdef ASCON128A
Bool ascon128A = True;
`else
Bool ascon128A = False;
`endif

module mkAscon(CryptoCoreIfc#(w__)) provisos (NumAlias#(w__, 32));
    let cipher <- mkAsconCipher(ascon128A);
    Byte padByte = 8'h80;
    let inLayer <- mkInputLayer(padByte);
    let outLayer <- mkOutputLayer;
    let bdiFlags <- mkReg(Flags {
        npub: False,
        ad: False,
        emptyAD: False,
        ct: False,
        ptct: False,
        hm: False,
        ptCtHm: False,
        ptCtAd: False
    });
    
    (* doc = "the output of inputLayer" *)
    let inBlock_probe <- mkProbe();

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
        Vector#(8, Bool) valids = replicate(True);
        outLayer.enq(unpack(zeroExtend(pack(out))), unpack(zeroExtend(pack(valids))));
    endrule 

  // ================================================== Interfaces ==================================================

    method Action start(OpFlags op);
        cipher.start(op);
    endmethod

    // Receive a word of the key
    method Action loadKey (Bit#(w__) data, Bool last);
        cipher.loadKey(data, last);
    endmethod

    method Action loadData (Bit#(w__) data, Bit#(TDiv#(w__, 8)) valid_bytes, Bit#(TDiv#(w__, 8)) pad_loc, Bool last, HeaderFlags flags);
        inLayer.put(unpack(pack(data)), valid_bytes, last && !flags.npub);
        bdiFlags <= Flags {
            npub: flags.npub,
            ad: flags.ad,
            emptyAD: flags.empty && flags.ad,
            ct: flags.ct,
            ptct: flags.ptct,
            hm: flags.hm,
            ptCtHm: !flags.npub && !flags.ad,
            ptCtAd: !flags.npub && !flags.hm
        };
        // TODO move to flags?
        // let firstAD = flags.ad && first_block;
        // let firstPtCt = flags.ptct && first_block;
        // let lastPtCt = flags.ptct && last;
        // let lastPtCtHash = last && !flags.npub && !flags.ad;
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
