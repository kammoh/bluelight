package BluelightUtils;

import Vector :: *;
import CryptoCore :: *;

typedef Bit#(8) Byte;
typedef Vector#(n_bytes, Byte) BlockOfSize#(numeric type n_bytes);
typedef Vector#(n_bytes, Bool) ByteValidsOfSize#(numeric type n_bytes);

function w2__ rotateLeft(w1__ w, Bit#(n) dummy) provisos (Bits#(w1__,a__), Bits#(w2__,a__), Add#(n,m,a__));
    Tuple2#(Bit#(n),Bit#(m)) s = split(pack(w));
    return unpack({tpl_2(s), tpl_1(s)});
endfunction

function w2__ rotateRight(w1__ w, Bit#(n) dummy) provisos (Bits#(w1__,a__), Bits#(w2__,a__), Add#(n,m,a__));
    Tuple2#(Bit#(m),Bit#(n)) s = split(pack(w));
    return unpack({tpl_2(s), tpl_1(s)});
endfunction



/// Move

typedef Tuple2#(BlockOfSize#(n_bytes), ByteValidsOfSize#(n_bytes)) OutType#(numeric type n_bytes);

interface InputLayerIfc#(numeric type n_bytes);
    method Action put(CoreWord word, Bool last, Bool pad, PadArg padarg, Bool empty);
    method ActionValue#(OutType#(n_bytes)) get;
    (* always_ready *)
    method Bool extraPad;
endinterface

interface CipherIfc#(numeric type n_bytes);
    // block in/out
    method ActionValue#(BlockOfSize#(n_bytes)) bin(BlockOfSize#(n_bytes) block, ByteValidsOfSize#(n_bytes) valids, Bool key, Bool ct, Bool ad, Bool npub, Bool hash, Bool first, Bool last); 
    // block out
    method ActionValue#(BlockOfSize#(n_bytes)) bout;
endinterface

interface OutputLayerIfc#(numeric type n_bytes);
    method Action enq(BlockOfSize#(n_bytes) block, ByteValidsOfSize#(n_bytes) valids);
    method Action deq;
    (* always_ready *)
    method Bool notEmpty;
    (* always_ready *)
    method CoreWord first;
    (* always_ready *)
    method Bool isLast;
endinterface

endpackage