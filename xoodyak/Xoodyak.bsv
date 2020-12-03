package Xoodyak;

import Vector::*;
import GetPut::*;
import XoodooDefs::*;
import SIPO::*;
import PISO::*;
import CryptoCore::*;
import BusAdaptor::*;

typedef enum {
  InIdle,
  InRecv, // wait for and recieve from bdi
  InFill
} InputState deriving(Bits, Eq);

typedef enum {
  Absorb,
  Permute
} TransformState deriving(Bits, Eq);

(* synthesize *)
module mkXoodyak(CryptoCoreIfc);
  SIPO#(MaxInRateLanes, XoodooLane)  sipo <- mkSIPO;
  PISO#(MaxOutRateLanes, XoodooLane) piso <- mkPISO;

  // FSM
  Reg#(TransformState) x_state <- mkReg(Absorb);
  Reg#(InputState)    in_state <- mkReg(InIdle);

  // Xoodoo
  Reg#(XoodooState) xoodooState <- mkRegU;

  Reg#(UInt#(TLog#(NumRounds))) round_counter <- mkRegU;

  Reg#(SegmentType) recv_type <- mkRegU;
  Reg#(Bool) last_word_padded <- mkRegU;

  Reg#(UInt#(TLog#(7))) out_lanes <- mkRegU;

  Reg#(Bool) zfilled <- mkRegU;
  Reg#(Bool) first_block <- mkRegU;
  Reg#(Bool) last_block  <- mkRegU;
  Reg#(Bool) full_block  <- mkRegU;
  Reg#(Bool) absorb_done <- mkRegU;

  function Byte udConst();
    case (recv_type) matches
      Key: return 8'h2;
      Npub: return 8'h3;
      AD: 
        case (tuple2(first_block,last_block)) matches
          {True,  True}: return 8'h83;
          {False, True}: return 8'h80;
          {True, False}: return 8'h03;
          default:       return 8'h00;
        endcase
      PT: return last_block ? 8'h40 : 0;
      default: return 8'h00;
    endcase
  endfunction : udConst

  function UInt#(TLog#(MaxInRateLanes)) xoodoo_last_laneCount();
    if ((recv_type == HM) || (recv_type == Key))
      return fromInteger(4 - 1);
    else
      if (recv_type == AD)
        return fromInteger(11 - 1);
      else
        return fromInteger(6 - 1);
  endfunction

  rule rl_absorb if ((in_state != InIdle) && (x_state == Absorb));
    sipo.deq;
    Vector#(6, XoodooLane) ct_in = take(sipo.data);
    // next in and x state:
    in_state <= last_block ? InIdle : InRecv;

    if(!absorb_done) x_state  <= Permute;

    round_counter <= 0;
    first_block <= False;

    Bit#(32) xoodoo_last_lane = recv_type == Key ? 0 : last(last(xoodooState));
    let xoredState11 = pack(sipo.data) ^ {pack(init(concat(xoodooState)))};

    let replaceBytes = recv_type == Key;

    absorb_done <= last_block && (recv_type == PT || recv_type == CT || recv_type == HM);

    xoodooState <= unpack({
      xoodoo_last_lane[31:24] ^ udConst, xoodoo_last_lane[23:1], xoodoo_last_lane[0] ^ pack(full_block && (recv_type == AD)),
      replaceBytes ? pack(sipo.data) : xoredState11
    });
    
    if (recv_type == PT) // TODO other:
    begin
      piso.enq(unpack(truncate(xoredState11)), out_lanes);
    end

  endrule

  (* fire_when_enabled, no_implicit_conditions *)
  rule rl_permute if (x_state == Permute);
    xoodooState <= round(xoodooState, round_counter);
    // $write("before round %d", round_counter);
    // dump_state(":", xoodooState);
    
    if (round_counter == 11)
      x_state <= Absorb;
    else
      round_counter <= round_counter + 1;
  endrule

  (* fire_when_enabled *)
  rule rl_fill_zero if (in_state == InFill && !sipo.isFull);
    zfilled <= True;
    if(!zfilled)
      out_lanes <= truncate(sipo.count);
      
    if (!zfilled && !last_word_padded)
      sipo.enq(recv_type == Key ? 'h100 : 1);
    else
      sipo.enq(0);
  endrule

  function XoodooLane pad_word(XoodooLane word, Bit#(2) padarg);
    return case (padarg)
      2'd1    : {zeroExtend(1'b1), word[7:0]};
      2'd2    : {zeroExtend(1'b1), word[15:0]};
      default : {zeroExtend(1'b1), word[23:0]};
    endcase;
  endfunction

  // typ:     SegmentType
  // pad:     number of padding byte on the last word of the input. 0 if all bytes are valid. maximum 3 if segment is not empty.
  // empty:   input is empty
  method Action receive(SegmentType typ, Bool empty) if (in_state == InIdle);
    recv_type   <= typ;
    first_block <= True;
    last_block  <= empty;
    zfilled     <= False;
    in_state    <= empty ? InFill : InRecv;
  endmethod

  method Action bdi(CoreWord word, Bool last, Bit#(2) padarg) if ((in_state == InRecv) && !sipo.isFull);
    let word_padded = last &&  (padarg != 0); 
    sipo.enq( word_padded ? pad_word(word, padarg) : word );
    let will_be_full = sipo.count() == xoodoo_last_laneCount();
    if (last || will_be_full)
      in_state <= InFill; // fill happens only if sipo not already full (i.e not AD full block)
    
    last_block <= last;
    full_block <= will_be_full;
    last_word_padded <= word_padded;
  endmethod

  interface FifoOut bdo;
    method deq      = piso.deq;
    method first    = piso.first;
    method notEmpty = piso.notEmpty;
  endinterface
  
endmodule : mkXoodyak

endpackage : Xoodyak