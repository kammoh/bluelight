package LwcApiDefines;


import Bus :: *;

(* always_ready, always_enabled *)
interface LwcDataOut#(type w);
  method w data;
  method Bool last;
  method Bool valid;
  (* prefix="" *)
  method Action ready((* port="ready" *) Bool value);
endinterface

interface LwcIfc#(numeric type w__);
    interface BusRecv#(Bit#(w__)) pdi;
    interface BusRecv#(Bit#(w__)) sdi;
    (* prefix = "do" *)
    interface LwcDataOut#(Bit#(w__)) do_;
endinterface

typedef enum {
    AD          = 4'b0001,
    Plaintext   = 4'b0100,
    Ciphertext  = 4'b0101,
    Npub        = 4'b1101,
    HashMessage = 4'b0111,
    Key         = 4'b1100,
    Tag         = 4'b1000,
    Digest      = 4'b1001
} SegmentType deriving (Bits, Eq, FShow);

// LWC instruction: high 4 bits of a PDI word
typedef enum {
    Op_ActKey = 4'b0111,
    Op_Enc    = 4'b0010,
    Op_Dec    = 4'b0011,
    Op_Hash   = 4'b0000
} OpCode deriving (Bits, Eq, FShow);

function OpCode getOpcode(Bit#(w__) w) provisos (Add#(something__, 4, w__));
    Bit#(4) msb4 = truncateLSB(w);
    return unpack(truncate(msb4));
endfunction

// third bit 1, on pdi, it's ACTKEY! (LDKEY is on sdi only)
function Bool opIsActKey(OpCode op) = pack(op)[2] == 1'b1;
function Bool opIsHash(OpCode op) = pack(op)[1] == 1'b0;
function Bool opIsDec(OpCode op) = pack(op)[2] == 1'b0 && pack(op)[0] == 1'b1;
function Bool opIsDecIfNotActKey(OpCode op) = pack(op)[0] == 1'b1;
function Bool opIsEnc(OpCode op) = pack(op)[1:0] == 2'b10;

// instance Bits#(OpCode, w__) provisos (Add#(something__, 4, w__)); // w__ >= 4
//     function Bit#(w__) pack (OpCode op);
//         return
//             case op
//                 Op_ActKey : 4'b0111;
//                 Op_Enc    : 4'b0010;
//                 Op_Dec    : 4'b0011;
//                 // Op_Hash   : 4'b0000;
//                 // default   : 4'b????;
//                 default   : 4'b0000;
//             endcase;
//     endfunction
//     function OpCode unpack (Bit#(w__) w);
//         Bit#(4) op = truncateLSB(w);
//         return
//             case op matches
//                 4'b?1?? : Op_ActKey;
//                 4'b??0? : Op_Hash;
//                 4'b???1 : Op_Dec;
//                 default : Op_Enc;
//             endcase;
//     endfunction
// endinstance

typedef Bit#(16) SegmentLength;

typedef struct {
    SegmentType seg_type;
    Bool eoi;
    Bool eot;
    Bool last;
    SegmentLength length;
} LwcHeader deriving (Eq, FShow);

typedef struct {
    SegmentType seg_type;
    Bool eoi;
    Bool eot;
    Bool last;
} LwcPartialHeader deriving (Eq, FShow);

typedef struct {
    SegmentType seg_type;
    Bool eot;
    Bool last;
    SegmentLength length;
} LwcOutHeader deriving (Eq, FShow);

instance Bits#(LwcOutHeader, w__) provisos (Add#(something__, 32, w__), Add#(something2__, 16, w__), Add#(something3__, 8, w__)); // w__ >= 32
    function Bit#(w__) pack (LwcOutHeader h);
        Bit#(4) typ = pack(h.seg_type);
        Bit#(4) flags = zeroExtend({1'b0, pack(h.eot), pack(h.last)});
        Bit#(16) len = pack(h.length);
        return reverseBits(zeroExtend(reverseBits({typ, flags, 8'b0, len}))); // pad with zeros on LSB (right)
    endfunction
    function LwcOutHeader unpack (Bit#(w__) w);
        Bit#(8) msb8 = truncateLSB(w);
        Bit#(16) len = truncate(w);
        return LwcOutHeader {
            seg_type: unpack(msb8[7:4]),
            last: unpack(msb8[2]),
            eot: unpack(msb8[1]),
            length: len
        };
    endfunction
endinstance

instance Bits#(LwcPartialHeader, w__) provisos (Add#(something__, 8, w__)); // w__ >= 8
    function Bit#(w__) pack (LwcPartialHeader h);
        Bit#(4) typ = pack(h.seg_type);
        Bit#(4) flags = zeroExtend({pack(h.eoi), pack(h.eot), pack(h.last)});
        return reverseBits(zeroExtend(reverseBits({typ, flags}))); // pad with zeros on LSB (right)
    endfunction
    function LwcPartialHeader unpack (Bit#(w__) w);
        Bit#(8) msb8 = truncateLSB(w);
        return LwcPartialHeader {
            seg_type: unpack(msb8[7:4]),
            last: unpack(msb8[2]),
            eot: unpack(msb8[1]),
            eoi: unpack(msb8[0])
        };
    endfunction
endinstance

instance Bits#(LwcHeader, w__) provisos (Add#(32, something__, w__), Add#(16, something2__, w__), Add#(8, something3__, w__)); // w__ >= 32
    function Bit#(w__) pack (LwcHeader h);
        Bit#(4) typ = pack(h.seg_type);
        Bit#(4) flags = {1'b0, pack(h.eoi), pack(h.eot), pack(h.last)};
        Bit#(16) len = pack(h.length);
        return reverseBits(zeroExtend(reverseBits({typ, flags, 8'b0, len})));
    endfunction
    function LwcHeader unpack (Bit#(w__) w);
        Bit#(8) msb8 = truncateLSB(w);
        Bit#(16) len = truncate(w);
        return LwcHeader {
            seg_type: unpack(msb8[7:4]),
            last: unpack(msb8[2]),
            eot: unpack(msb8[1]),
            eoi: unpack(msb8[0]),
            length: unpack(len)
        };
    endfunction
endinstance

endpackage : LwcApiDefines