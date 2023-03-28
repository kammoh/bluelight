package AsconRound;

import Vector :: *;
import BluelightUtils :: *;



typedef Bit#(64) AsconWord;
typedef 12 PaRounds;
typedef Vector#(5, AsconWord) AsconState; // S_r (rate)
typedef Byte RoundConstant;

`ifdef ASCON128A
typedef 8 PbRounds; // Ascon-128: 6, Ascon-128a: 8
typedef 2 RateWords; // Ascon-128/Ascon-Hash/Ascon-XOF: 1, Ascon-128a: 2
`else
typedef 6 PbRounds; // Ascon-128: 6, Ascon-128a: 8
typedef 1 RateWords; // Ascon-128/Ascon-Hash/Ascon-XOF: 1, Ascon-128a: 2
`endif

// `define LUT_SUBS

`ifndef UNROLL_FACTOR
`define UNROLL_FACTOR 1
`endif
// Ascon-128: 1,2,3,6
// Ascon-128a: 1,2,4
typedef `UNROLL_FACTOR UnrollFactor;

function RoundConstant initRC(Bool pb);
    return pb ? (valueOf(PbRounds) == 8 ? 8'hb4 : 8'h96) : 8'hf0;
endfunction

function RoundConstant nextRC(RoundConstant rc);
    Tuple2#(Bit#(4),Bit#(4)) s = split(rc);
    return {tpl_1(s) - 1, tpl_2(s) + 1};
endfunction


instance Bitwise #(Vector#(n__, e__)) provisos (Bits#(e__, se__), Literal#(e__));
    function Vector#(n__, e__) \& (Vector#(n__, e__) x1, Vector#(n__, e__) x2) = unpack(pack(x1) & pack(x2));
    function Vector#(n__, e__) \| (Vector#(n__, e__) x1, Vector#(n__, e__) x2) = unpack(pack(x1) | pack(x2));
    function Vector#(n__, e__) \^ (Vector#(n__, e__) x1, Vector#(n__, e__) x2) = unpack(pack(x1) ^ pack(x2));
    function Vector#(n__, e__) \~^ (Vector#(n__, e__) x1, Vector#(n__, e__) x2) = unpack(pack(x1) ~^ pack(x2));
    function Vector#(n__, e__) \^~ (Vector#(n__, e__) x1, Vector#(n__, e__) x2) = unpack(pack(x1) ^~ pack(x2));
    function Vector#(n__, e__) invert (Vector#(n__, e__) x1) = unpack(~pack(x1));
    function Vector#(n__, e__) \<< (Vector#(n__, e__) lhs, t__ rhs) provisos (PrimShiftIndex#(t__, a__)) =
        shiftOutFromN(fromInteger(0), lhs, rhs);
    function Vector#(n__, e__) \>> (Vector#(n__, e__) lhs, t__ rhs) provisos (PrimShiftIndex#(t__, a__)) =
        shiftOutFrom0(fromInteger(0), lhs, rhs);
    function Bit#(1) msb (Vector#(n__, e__) x) = msb(pack(x));
    function Bit#(1) lsb (Vector#(n__, e__) x) = lsb(pack(x));
endinstance

function AsconState linearDiffusion(AsconState s);
    AsconState x = newVector;
    x[0] = s[0] ^ rotateRight(s[0], 19'b0) ^ rotateRight(s[0], 28'b0);
    x[1] = s[1] ^ rotateRight(s[1], 61'b0) ^ rotateRight(s[1], 39'b0);
    x[2] = s[2] ^ rotateRight(s[2],  1'b0) ^ rotateRight(s[2],  6'b0);
    x[3] = s[3] ^ rotateRight(s[3], 10'b0) ^ rotateRight(s[3], 17'b0);
    x[4] = s[4] ^ rotateRight(s[4],  7'b0) ^ rotateRight(s[4], 41'b0);
    return x;
endfunction

/// Same as Keccak S-Box
function Vector#(5, Bit#(w__)) chi (Vector#(5, Bit#(w__)) s);
    return s ^ rotate(~s & rotate(s)); // rotate right
endfunction

function AsconState substitution(AsconState s);
    AsconState x = newVector;
`ifdef LUT_SUBS
    Bit#(5) sbox[32] = {5'h4,  5'hb, 5'h1f, 5'h14, 5'h1a, 5'h15,  5'h9,  5'h2, 5'h1b, 5'h5, 5'h8, 5'h12, 5'h1d, 5'h3, 5'h6, 5'h1c, 
                       5'h1e, 5'h13,  5'h7,  5'he,  5'h0,  5'hd, 5'h11, 5'h18, 5'h10, 5'hc, 5'h1, 5'h19, 5'h16, 5'ha, 5'hf, 5'h17};
    for (Integer i = 0; i < 64; i = i + 1) begin
        Bit#(5) sin;
        for (Integer j = 0; j < 5; j = j + 1)
            sin[4-j] = s[j][i];
        let sout = sbox[sin];
        for (Integer j = 0; j < 5; j = j + 1)
            x[j][i] = sout[4-j];
    end
`else
    x[0] = s[0] ^ s[4];
    x[1] = s[1];
    x[2] = s[2] ^ s[1];
    x[3] = s[3];
    x[4] = s[4] ^ s[3];
    // AsconState t = newVector;
    // start of keccak s-box
    // t[0] = ~x[0] & x[1];
    // t[1] = ~x[1] & x[2];
    // t[2] = ~x[2] & x[3];
    // t[3] = ~x[3] & x[4];
    // t[4] = ~x[4] & x[0];
    // x[0] = x[0] ^ t[1];
    // x[1] = x[1] ^ t[2];
    // x[2] = x[2] ^ t[3];
    // x[3] = x[3] ^ t[4];
    // x[4] = x[4] ^ t[0];
    x = chi(x);
    // end of keccak s-box
    x[1] = x[1] ^ x[0];
    x[0] = x[0] ^ x[4];
    x[3] = x[3] ^ x[2];
    x[2] = ~x[2];
`endif
    return x;
endfunction

function Tuple2#(AsconState,RoundConstant) permutation(AsconState s, RoundConstant rc);
    for (Integer i = 0; i < valueOf(UnrollFactor); i = i + 1) begin
        s[2][7:0] = s[2][7:0] ^ rc;
        s = substitution(s);
        s = linearDiffusion(s);
        rc = nextRC(rc);
    end
    return tuple2(s, rc);
endfunction

endpackage