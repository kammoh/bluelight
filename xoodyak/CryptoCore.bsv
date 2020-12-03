package CryptoCore;

import GetPut::*;
import BusAdaptor::*;

typedef Bit#(8) Byte;

// TODO configurable, maybe through preprocessor?
typedef Bit#(32) CoreWord;

typedef enum {
  AD        = 4'b0001,
  PT        = 4'b0100,
  CT        = 4'b0101,
  Tag       = 4'b1000,
  Key       = 4'b1100,
  Npub      = 4'b1101,
  HM        = 4'b0111
} SegmentType deriving (Bits, Eq);


interface CryptoCoreIfc;
  method Action receive(SegmentType typ, Bool empty);
  method Action bdi(CoreWord word, Bool last, Bit#(2) padarg);
  interface FifoOut#(CoreWord) bdo;
endinterface

endpackage : CryptoCore