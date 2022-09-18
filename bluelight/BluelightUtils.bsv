package BluelightUtils;

import Vector     :: *;
import CryptoCore :: *;

export CryptoCore     :: *;
export BluelightUtils :: *;

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

function w2__ swapEndian(w1__ word) provisos (Bits#(w1__, n), Bits#(w2__, n), Mul#(nbytes, SizeOf#(Byte), n), Div#(n, SizeOf#(Byte), nbytes));
    Vector#(nbytes, Byte) v = toChunks(pack(word));
    return unpack(pack(reverse(v)));
endfunction

function w__ _xor (w__ a, w__ b) provisos (Bitwise#(w__)) = a ^ b;

function Vector#(n, w__) xorVecs(Vector#(n, w__) v1, Vector#(n, w__) v2)
    provisos (Bits#(w__, w_bits__), Bitwise#(w__), Add#(1, a__, n)) = zipWith(_xor, v1, v2);


endpackage
