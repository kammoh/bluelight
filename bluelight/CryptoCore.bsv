package CryptoCore;

import GetPut :: *;
import FIFOF  :: *;
import Vector :: *;
import BluelightUtils :: *;

export Vector     :: *;
export CryptoCore :: *;

`ifndef IO_WIDTH
`define IO_WIDTH 32
`endif

typedef Bit#(`IO_WIDTH) CoreWord;
typedef Bit#(8) Byte;
typedef TDiv#(SizeOf#(CoreWord),SizeOf#(Byte)) CoreWordBytes;
typedef Bit#(2) PadArg;

// TODO change to CryptoCore parameter, constant, or `define?
// used in LwcApi
Integer crypto_abytes = 16;     // size of tag in bytes
Integer crypto_hash_bytes = 32; // size of hash digest in bytes
typedef TDiv#(128,`IO_WIDTH) CryptoKeyWords; // size of key

interface FifoOut#(type a__);
    method Action deq;
    (* always_ready *)
    method Bool notEmpty;
    (* always_ready *)
    method a__ first;
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

function w__ enableBits(Bool en, w__ b) provisos (Bits#(w__, n__), Literal#(w__), Add#(1, a__, n__)) = en ? b : 0;

function w__ padOutWord (w__ w, ValidBytes#(w__) valids) provisos (Bits#(w__, w_bits__), Mul#(w_bytes__, SizeOf#(Byte), w_bits__), Div#(w_bits__, SizeOf#(Byte), w_bytes__));
    Vector#(w_bytes__, Byte) first_bytes = toChunks(w);
    Vector#(w_bytes__, Bool) valid_bytes = map(unpack, toChunks(valids));
    return unpack(pack(zipWith(enableBits, valid_bytes, first_bytes)));
endfunction

function CoreWord padInWord (CoreWord word, ValidBytes#(CoreWord) valids, Byte padByte) =
    case (valids) matches
        4'b1??? : word;
        4'b?1?? : {padByte, word[23:0]};
        4'b??1? : {zeroExtend(padByte), word[15:0]};
        default : {zeroExtend(padByte), word[7:0]};
    endcase;

function w__ padInWord80 (w__ w, ValidBytes#(w__) valids) provisos (Bits#(w__, w_bits__), Mul#(w_bytes__, SizeOf#(Byte), w_bits__), Div#(w_bits__, SizeOf#(Byte), w_bytes__), Add#(1, a__, w_bytes__));
    function Byte f3(Bool en, Bool en_1, Byte b) = en ? b : {pack(en_1), 0};
    Vector#(w_bytes__, Byte) first_bytes = toChunks(w);
    Vector#(w_bytes__, Bool) valid_bytes = map(unpack, toChunks(valids));
    let r = cons(head(first_bytes), zipWith3(f3, tail(valid_bytes), init(valid_bytes), tail(first_bytes)) );
    return unpack(pack(r));
endfunction

typedef struct {
    Bool last;  // last word of the type
    w__  data;  // data word
} WithLast#(type w__)  deriving (Bits, Eq, FShow);

typedef struct{
    Bool npub;  // nonce public
    Bool ad;    // associated data
    Bool pt;    // plaintext
    Bool ct;    // ciphertext
    Bool ptct;  // PT or CT
    Bool hm;    // hash message
    Bool empty; // empty
    Bool eoi;   // end of input: The segment is the last input segment other than TAG.
} HeaderFlags deriving(Bits, Eq, FShow);

typedef struct {
    Bool new_key; // operation requires a new key
    Bool decrypt; // operation is decryption
    Bool hash;    // operation is hashing
} OpFlags deriving(Bits, Eq, FShow);

interface CryptoCoreIfc;
    // initialize CC for the operation [Optional]
    method Action initOp (OpFlags flags);

    // Recieve a word of the key
    method Action key (CoreWord w, Bool last);

    // Recieve a word of Public Nonce, Associated Data, Plaintext, Ciphertext, or Hash Message
    // data:        data word
    // valid_bytes: bit array indicating which bytes in `data` are valid
    // last:        this is the last word of the type
    method Action bdi (CoreWord data, ValidBytes#(CoreWord) valid_bytes, Bool last, HeaderFlags flags);

    // output from CryptoCore: Send a word of Plaintext, Ciphertext, Tag, or Digest
    interface FifoOut#(WithLast#(CoreWord)) bdo;

endinterface

function w__ swapEndian(w__ word) provisos (Bits#(w__, n), Mul#(nbytes, SizeOf#(Byte), n), Div#(n, SizeOf#(Byte), nbytes));
    Vector#(nbytes, Byte) v = toChunks(pack(word));
    return unpack(pack(reverse(v)));
endfunction

endpackage : CryptoCore
