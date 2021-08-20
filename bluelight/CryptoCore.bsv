package CryptoCore;

import GetPut :: *;
import FIFOF  :: *;
import Vector :: *;

export Vector     :: *;
export CryptoCore :: *;

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
typedef TDiv#(128,`IO_WIDTH) CryptoKeyWords; // size of key

interface FifoOut#(type a);
    method Action deq;
    (* always_ready *)
    method Bool notEmpty;
    (* always_ready *)
    method a first;
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

typedef struct {
    Bool last;      // last word of the type
    PadArg padarg;  // padding argument, number of valid bytes or 0 all valid
    CoreWord word;  // data word
} BdIO deriving (Bits, Eq);

typedef struct{
    Bool npub;  // nonce public
    Bool ad;    // associated data
    Bool pt;    // plaintext
    Bool ct;    // ciphertext
    Bool ptct;  // PT or CT
    Bool hm;    // hash message
    Bool empty; // empty: The upcoming segment is empty. No subsequent bdi calls will occur for this type.
    Bool eoi;   // end of input: The upcoming segment is the last input segment other than TAG.
} HeaderFlags deriving(Bits, Eq, FShow);

typedef struct {
    Bool new_key; // operation requires a new key
    Bool decrypt; // operation is decryption
    Bool hash;    // operation is hashing
} OpFlags deriving(Bits, Eq, FShow);

interface CryptoCoreIfc;
    // initialize CC for the operation [Optional]
    method Action init (OpFlags flags);

    // meta-data, header
    // after fire, anticipate bdi words of this type, unless flags.empty == True.
    method Action anticipate (HeaderFlags flags);

    // Recieve a word of the key
    method Action key (CoreWord w, Bool last);

    // Recieve a word of Public Nonce, Associated Data, Plaintext, Ciphertext, or Hash Message
    method Action bdi (BdIO i);

    // output from CryptoCore: Send a word of Plaintext, Ciphertext, Tag, or Digest
    interface FifoOut#(BdIO) bdo;

endinterface

function w__ swapEndian(w__ word) provisos (Bits#(w__, n), Mul#(nbytes, SizeOf#(Byte), n), Div#(n, SizeOf#(Byte), nbytes));
    Vector#(nbytes, Byte) v = toChunks(pack(word));
    return unpack(pack(reverse(v)));
endfunction

endpackage : CryptoCore