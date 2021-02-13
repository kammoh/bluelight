package CryptoCore;

import GetPut::*;
import FIFOF::*;
import Vector::*;

`ifndef IO_WIDTH
`define IO_WIDTH 32
`endif

typedef Bit#(`IO_WIDTH) CoreWord;
typedef Bit#(8) Byte;
typedef TDiv#(SizeOf#(CoreWord),SizeOf#(Byte)) CoreWordBytes;
typedef Bit#(2) PadArg;

// TODO FIXME as cryptoCore parameter or constant? `define?
// used in LwcApi
Integer crypto_abytes = 16;     // size of tag in bytes
Integer crypto_hash_bytes = 32; // size of hash digest in bytes

interface FifoOut#(type a);
    method Action deq;
    (* always_ready *)
    method Bool notEmpty;
    (* always_ready *)
    method a first;
endinterface

interface FifoIn#(type a);
    method Action enq(a el);
endinterface

function FifoOut#(a) fifofToFifoOut(FIFOF#(a) fifo);
    return interface FifoOut#(a);
            method Action deq if (fifo.notEmpty);
                fifo.deq;
            endmethod
            method Bool notEmpty = fifo.notEmpty;
            method a first = fifo.first;
        endinterface;
endfunction

function Tuple2#(Bool, CoreWord) padWord(CoreWord word, PadArg padarg, Byte padByte);
    return case (padarg)
        2'd0    : tuple2(False, word);
        2'd1    : tuple2(True, {zeroExtend(padByte), word[7:0]});
        2'd2    : tuple2(True, {zeroExtend(padByte), word[15:0]});
        default : tuple2(True, {padByte, word[23:0]});
    endcase;
endfunction

typedef enum {
    AD          = 4'b0001,
    Plaintext   = 4'b0100,
    Ciphertext  = 4'b0101,
    Tag         = 4'b1000,
    Key         = 4'b1100,
    Npub        = 4'b1101,
    HashMessage = 4'b0111,
    Digest      = 4'b1001
} SegmentType deriving (Bits, Eq, FShow);

// LSB of LWC instruction
// typedef enum {
//     ACTKEY  = 4'b111, // -> 01 CoreOpType::OpKey  
//     ENC     = 4'b010, // -> 10 CoreOpType::OpEnc  
//     DEC     = 4'b011, // -> 11 CoreOpType::OpDec  
//     HASH    = 4'b000  // -> 00 CoreOpType::OpHash 
// } OpCode deriving (Bits, Eq, FShow);
typedef Bit#(3) OpCode;

// typedef enum {
//     OpHash  = 2'b00,
//     OpOther = 2'b01,
//     OpEnc   = 2'b10,
//     OpDec   = 2'b11,
// } CoreOpType deriving (Bits, Eq, FShow);

// function CoreOpType opCodeToCoreOpCode(OpCode op);
//     return unpack(pack(op)[1:0]);
// endfunction

typedef struct {
    Bool lot;       // last word of the type
    PadArg padarg;  // padding argument, number of valid bytes or 0 all valid
    CoreWord word;  // data word
} BdIO deriving (Bits, Eq);

function Bool opCodeIsHash(OpCode op);
    return pack(op)[1] == 0;
endfunction

interface CryptoCoreIfc;
    // after fire, words of type `typ` will be sent to CryptoCore, if not empty
    // typ:   type of segment to be received (if note empty) and processed
    // empty: no bdi will be sent afterwards
    method Action process(SegmentType typ, Bool empty, Bool eoi);

    // optionally initialize CC for the operation
    method Action init(OpCode op);

    // input to CryptoCore
    interface FifoIn#(BdIO)  bdi;

    // output from CryptoCore
    interface FifoOut#(BdIO) bdo;
endinterface

function w__ swapEndian(w__ word) provisos (Bits#(w__, n), Mul#(nbytes, SizeOf#(Byte), n), Div#(n, SizeOf#(Byte), nbytes));
    Vector#(nbytes, Byte) v = toChunks(pack(word));
    return unpack(pack(reverse(v)));
endfunction

endpackage : CryptoCore