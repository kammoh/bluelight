package LWC;

import FIFO::*;
import GetPut::*;
import BusAdaptor::*;
import CryptoCore::*;
import Xoodyak::*;

typedef enum {
  ACTKEY  = 4'b111, // -> 01
  ENC     = 4'b010, // -> 10
  DEC     = 4'b011, // -> 11
  HASH    = 4'b000  // -> 00
} LwcApiPdiOpcodeLSB deriving (Bits, Eq);

interface LWCIfc;
  interface BusRecv#(CoreWord) pdi;
  interface BusRecv#(CoreWord) sdi;
  interface BusSend#(CoreWord) pdo;
endinterface

typedef enum {
  PdiInstruction,
  SdiInstruction, // utter nonsense!
  PdiHeader,      // segment header
  SdiHeader,
  PdiData,        // segment data
  SdiData
} InputStateType deriving (Bits, Eq);

module mkLWC#(CryptoCoreIfc cryptoCore) (LWCIfc);
  let pdo_sender <- mkBusSender(cryptoCore.bdo);
  BusReceiver#(CoreWord) pdi_receiver <- mkBusReceiver;
  BusReceiver#(CoreWord) sdi_receiver <- mkBusReceiver;

  Reg#(Bit#(14)) segment_word_counter <- mkRegU;
  Reg#(Bit#(2)) segment_last_remain   <- mkRegU;

  Reg#(Bool) segment_last <- mkRegU; // current segment is the last segment
  Reg#(Bool) segment_eot  <- mkRegU; // current segment is the last segment of its type
  Reg#(Bool) segment_eoi  <- mkRegU;

  let state <- mkReg(PdiInstruction);

  (* fire_when_enabled *)
  rule rl_pdi_instruction if (state == PdiInstruction);
    let tg <- pdi_receiver.tryGet(); 
    if (tg matches tagged Valid .w)
    begin
      Bit#(4) op_code = truncateLSB(w); // only need 3 bits (LSB) really
      // thrid bit 1, on pdi, it's ACTKEY! (LDKEY is on sdi only)
      state <= op_code[2] == 1'b1 ? SdiInstruction : PdiHeader;
    end
  endrule

  (* fire_when_enabled, no_implicit_conditions *)
  rule rl_get_sdi_inst if (state == SdiInstruction);
    let tg <- sdi_receiver.tryGet(); 
    if (isValid(tg))
      state <= SdiHeader;
  endrule

  (* fire_when_enabled *)
  rule rl_get_hdr if ((state == SdiHeader) || (state == PdiHeader));
    let tg <- (state == SdiHeader) ? sdi_receiver.tryGet() : pdi_receiver.tryGet(); 
    if (tg matches tagged Valid .w)
    begin

      let segment_type  = w[31:28];
      let segment_len   = w[15:0];
      let empty = segment_len == 0;

      let last_segment = unpack(w[24]);
      segment_last <= last_segment;
      segment_eot  <= unpack(w[25]);
      segment_eoi  <= unpack(w[26]);
      segment_word_counter <= segment_len[15:2];
      segment_last_remain  <= segment_len[1:0];

      cryptoCore.receive(unpack(segment_type), empty);
      state <= (empty && last_segment) ? PdiInstruction : (state == SdiHeader) ? SdiData : PdiData;
    end
  endrule

  (* fire_when_enabled *)
  rule rl_get_key if ((state == SdiData) || (state == PdiData));
    let tg <- (state == SdiData) ? sdi_receiver.tryGet() : pdi_receiver.tryGet();
    if (tg matches tagged Valid .w)
    begin
      segment_word_counter <= segment_word_counter - 1;

      let up_zero = segment_word_counter[13:1] == 0;
      let lsb_zero = segment_word_counter[0] == 0;
      let remainder_zero = segment_last_remain == 0;

      let last = up_zero && (lsb_zero || remainder_zero);

      cryptoCore.bdi(w, last, segment_last_remain); // 0 -> no padding 1 -> 3, 2-> 2, 3-> 1

      if (last) // assuming segment_last is true for Key on SDI
        state <= segment_last ? PdiInstruction : PdiHeader;
    end
  endrule
  
  interface pdi = pdi_receiver.in;
  interface sdi = sdi_receiver.in;
  interface pdo = pdo_sender;

endmodule

endpackage : LWC