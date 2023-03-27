package CryptoCore;

import GetPut::*;
import FIFOF::*;
import Vector::*;

`ifndef IO_WIDTH
`define IO_WIDTH 32
`endif

typedef Bit#(`IO_WIDTH) CoreWord;

// TODO FIXME as cryptoCore parameter or constant? `define?
// used in LwcApi
Integer crypto_abytes = 16;     // size of tag in bytes
Integer crypto_hash_bytes = 32; // size of hash digest in bytes

typedef Bit#(8) Byte;

typedef Bit#(TDiv#(SizeOf#(w__), SizeOf#(Byte))) ValidBytes#(type w__);

interface FifoOut#(type a);
  method Action deq;
  (* always_ready *)
  method Bool notEmpty;
  (* always_ready *)
  method a first;
endinterface

function FifoOut#(a) fifofToFifoOut(FIFOF#(a) fifo);
return
  interface FifoOut#(a);
    method Action deq = fifo.deq;
    method Bool notEmpty = fifo.notEmpty;
    method a first = fifo.first;
  endinterface;
endfunction

function Tuple2#(Bool, CoreWord) padWord32(CoreWord word, Bit#(2) padarg, Bool padOne);
  return case (padarg)
    2'd0    : tuple2(False, word);
    2'd1    : tuple2(True, {zeroExtend(pack(padOne)), word[7:0]});
    2'd2    : tuple2(True, {zeroExtend(pack(padOne)), word[15:0]});
    default : tuple2(True, {zeroExtend(pack(padOne)), word[23:0]});
  endcase;
endfunction


function w__ padInWord (w__ w, ValidBytes#(w__) valids, Byte pad_byte) provisos (Bits#(w__, w_bits__), Mul#(w_bytes__, SizeOf#(Byte), w_bits__), Div#(w_bits__, SizeOf#(Byte), w_bytes__), Add#(1, a__, w_bytes__));
    function Byte f3(Bool en, Bool en_pad, Byte b) = en ? b : en_pad ? pad_byte : 0;
    Vector#(w_bytes__, Byte) bytes = toChunks(w);
    Vector#(w_bytes__, Bool) valid_bytes = map(unpack, toChunks(valids));
    let r = zipWith3(f3, valid_bytes, cons(True, init(valid_bytes)), bytes );
    return unpack(pack(r));
endfunction

function w__ clear_invalid_bytes (w__ w, ValidBytes#(w__) valids) provisos (Bits#(w__, w_bits__), Mul#(w_bytes__, SizeOf#(Byte), w_bits__), Div#(w_bits__, SizeOf#(Byte), w_bytes__), Add#(1, a__, w_bytes__));
    function Byte clr(Bool en, Byte b) = en ? b : 0;
    Vector#(w_bytes__, Byte) bytes = toChunks(w);
    Vector#(w_bytes__, Bool) valid_bytes = map(unpack, toChunks(valids));
    return unpack(pack(zipWith(clr, valid_bytes, bytes)));
endfunction
function w__ clear_invalid_bytes_cond (w__ w, ValidBytes#(w__) valids, Bool cond) provisos (Bits#(w__, w_bits__), Mul#(w_bytes__, SizeOf#(Byte), w_bits__), Div#(w_bits__, SizeOf#(Byte), w_bytes__), Add#(1, a__, w_bytes__));
    function Byte clr(Bool en, Byte b) = (!cond || en) ? b : 0;
    Vector#(w_bytes__, Byte) bytes = toChunks(w);
    Vector#(w_bytes__, Bool) valid_bytes = map(unpack, toChunks(valids));
    return unpack(pack(zipWith(clr, valid_bytes, bytes)));
endfunction

function Bit#(w__) pad10 (Bit#(w__) data, Bit#(TDiv#(w__, 8)) pad_loc) provisos (Mul#(w_bytes__, 8, w_bits__), Div#(w__, 8, w_bytes__), Add#(1, a__, w_bytes__));
    for (Integer i = 0; i < valueOf(w_bytes__); i = i + 1)
      if (pad_loc[i] == 1'b1)
        data[i * 8] = 1'b1;
    return data;
endfunction

typedef struct {
    Bool last;  // last word of the type
    w__  data;  // data word
} WithLast#(type w__)  deriving (Bits, Eq, FShow);

typedef struct{
    Bool npub;         // nonce public
    Bool ad;           // associated data
    Bool pt;           // plaintext
    Bool length;       // length
    Bool ct;           // ciphertext
    Bool ptct;         // PT or CT
    Bool hm;           // hash message
    Bool empty;        // empty
    Bool end_of_input; // last input type sent
} HeaderFlags deriving(Bits, Eq, FShow);

typedef struct {
    Bool new_key; // operation requires a new key
    Bool decrypt; // operation is decryption
    Bool hash;    // operation is hashing
} OpFlags deriving(Bits, Eq, FShow);

interface CryptoCoreIfc #(parameter numeric type w__);
    // Start a new operation
    method Action start (OpFlags op);

    // Receive one word of the key
    method Action loadKey (Bit#(w__) data, Bool last);
  
    // Receive one word of data (Public Nonce, Associated Data, Plaintext, Ciphertext, or Hash Message)
    // data:        data word
    // valid_bytes: bit array indicating which bytes in `data` are valid
    // pad_loc:     location of byte to be padded
    // last:        this is the last word of the type
    method Action loadData (Bit#(w__) data, Bit#(TDiv#(w__, 8)) valid_bytes, Bit#(TDiv#(w__, 8)) pad_loc, Bool last, HeaderFlags flags);

    // output from CryptoCore: Send a word of Plaintext, Ciphertext, Tag, or Digest
    interface FifoOut#(WithLast#(CoreWord)) data_out;
endinterface

function Bit#(n) swapEndian(Bit#(n) word) provisos (Mul#(nbytes, 8, n),Div#(n, 8, nbytes));
    Vector#(nbytes, Byte) v = toChunks(word);
    return pack(reverse(v));
endfunction

endpackage : CryptoCore