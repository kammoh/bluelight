package CryptoCore;

import GetPut::*;
import FIFOF::*;
import Vector::*;

`ifndef IO_WIDTH
`define IO_WIDTH 32
`endif

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
return
  interface FifoOut#(a);
    method Action deq = fifo.deq;
    method Bool notEmpty = fifo.notEmpty;
    method a first = fifo.first;
  endinterface;
endfunction

function Tuple2#(Bool, CoreWord) padWord(CoreWord word, Bit#(2) padarg, Bool padOne);
  return case (padarg)
    2'd0    : tuple2(False, word);
    2'd1    : tuple2(True, {zeroExtend(pack(padOne)), word[7:0]});
    2'd2    : tuple2(True, {zeroExtend(pack(padOne)), word[15:0]});
    default : tuple2(True, {zeroExtend(pack(padOne)), word[23:0]});
  endcase;
endfunction

typedef Bit#(8) Byte;

// TODO configurable, maybe through preprocessor?
typedef Bit#(`IO_WIDTH) CoreWord;

typedef enum {
  AD     = 4'b0001,
  PT     = 4'b0100,
  CT     = 4'b0101,
  Tag    = 4'b1000,
  Key    = 4'b1100,
  Npub   = 4'b1101,
  HM     = 4'b0111,
  Digest = 4'b1001
} SegmentType deriving (Bits, Eq, FShow);

typedef enum {
  OpKey  = 2'b01,
  OpEnc  = 2'b10,
  OpDec  = 2'b11,
  OpHash = 2'b00
} CoreOpType deriving (Bits, Eq, FShow);

typedef struct {
  CoreWord word;  // data word
  Bool lot;       // last word of the type
  Bit#(2) padarg; // padding argument, number of valid bytes or 0 all valid
} BdIO deriving (Bits, Eq);

interface CryptoCoreIfc;
  // after fire, words of type `typ` will be sent to CryptoCore, if not empty
  method Action receive(SegmentType typ, Bool empty);
  
  // input to CryptoCore
  interface FifoIn#(BdIO)  bdi;

  // output from CryptoCore
  interface FifoOut#(BdIO) bdo;
endinterface

function Bit#(n) swapEndian(Bit#(n) word) provisos (Mul#(nbytes, 8, n),Div#(n, 8, nbytes));
    Vector#(nbytes, Byte) v = toChunks(word);
    return pack(reverse(v));
endfunction

endpackage : CryptoCore