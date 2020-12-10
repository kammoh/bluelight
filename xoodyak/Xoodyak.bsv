package Xoodyak;

import Vector::*;
import GetPut::*;

import XoodooDefs::*;
import SIPO::*;
import PISO::*;
import CryptoCore::*;

typedef enum {
  InIdle, // waiting to receive command
  InRecv, // recieve from bdi
  InFill
} InputState deriving(Bits, Eq);

typedef enum {
  Absorb,
  Permute,
  Squeeze
} TransformState deriving(Bits, Eq);

// (* synthesize *)
module mkXoodyak(CryptoCoreIfc);
  SIPO#(MaxInRateLanes, XoodooLane)  sipo <- mkSIPO;
  PISO#(MaxOutRateLanes, XoodooLane) piso <- mkPISO;

  // 1 bit for each byte in every the input sipo lane
  // make it simple, use MaxInRateLanes lanes, TODO? use just MaxOutRateLanes
  MyShiftReg#(MaxInRateLanes, Bit#(4)) sipoFlags <- mkMyShiftReg;

  // FSMs
  Reg#(TransformState) xState <- mkReg(Absorb); // transform state
  Reg#(InputState)    inState <- mkReg(InIdle); // input state

  // Xoodoo
  Reg#(XoodooState) xoodooState <- mkRegU;

  Reg#(UInt#(TLog#(NumRounds))) round_counter <- mkRegU;

  Reg#(SegmentType) recv_type <- mkRegU;
  Reg#(Bool) last_word_padded <- mkRegU;

  Reg#(UInt#(TLog#(7))) sipoValidLanes <- mkRegU;

  Reg#(Bit#(2)) inPadarg  <- mkRegU;
  Reg#(Bit#(2)) outPadarg <- mkRegU;

  Reg#(Bool) zfilled <- mkRegU;
  Reg#(Bool) inFirstBlock  <- mkRegU;
  Reg#(Bool) inLastBlock   <- mkRegU; // last block of the segment
  Reg#(Bool) outLastBlock  <- mkReg(False);
  Reg#(Bool) fullAdBlock   <- mkRegU;
  Reg#(Bool) firstSqueeze  <- mkRegU;
  Reg#(Bool) secondSqueeze <- mkRegU;

  function Byte udConst();
    return case (recv_type)
      Key:  8'h2;
      Npub: 8'h3;
      AD: 
        case (tuple2(inFirstBlock,inLastBlock)) matches
          {True,  True}: 8'h83;
          {False, True}: 8'h80;
          {True, False}: 8'h03;
          default:       8'h00;
        endcase
      PT, CT: (inLastBlock ? 8'h40 : 0);
      HM: (inFirstBlock ? 8'h01 : 8'h00);
      default: 8'h00;
    endcase;
  endfunction : udConst

  (* fire_when_enabled *)
  rule rl_absorb if (sipo.isFull && (inState != InIdle) && (xState == Absorb) && !piso.notEmpty);
    sipo.deq;
    
    // always permute after absorb
    xState <= Permute;

    round_counter <= 0;
    inFirstBlock <= False;
    zfilled      <= False;


    if (inLastBlock && (recv_type == PT || recv_type == CT || recv_type == HM)) begin
      outPadarg <= recv_type == HM ? 0 : inPadarg;
      firstSqueeze <= True;
      secondSqueeze <= recv_type == HM;
    end else begin
      outPadarg <= 0;
      firstSqueeze  <= False;
      secondSqueeze <= False;
    end
    inState <= inLastBlock ? InIdle : InRecv;
    inLastBlock <= False;

    
    // $displayh("flags: ", sipoFlags.data);

    /// update xoodooState: ////
    Vector#(12, XoodooLane) nextState;
    let currentState = concat(xoodooState);
    Vector#(11, XoodooLane) inputXorState = toChunks(pack(sipo.data) ^ pack(init(concat(xoodooState))) );
    Integer i;
    for (i=0; i<11; i=i+1) begin
      let d = sipo.data[i];
      let x = inputXorState[i];
      let lane = case (sipoFlags.data[i])
        4'b0001 : {x[31:8],  d[7:0]};
        4'b0011 : {x[31:16], d[15:0]};
        4'b0111 : {x[31:24], d[23:0]};
        4'b1111 : d;
        default : x;
      endcase;
      nextState[i] = case (recv_type)
        Key, CT: lane; // replace flagged bytes
        HM : (inFirstBlock ? lane : x);
        default : x;
      endcase;
    end
    XoodooLane lastLane = ((recv_type == Key) || ((recv_type == HM) && inFirstBlock)) ? 0 : last(currentState);
    nextState[11] = {lastLane[31:24] ^ udConst, lastLane[23:1], lastLane[0] ^ pack(fullAdBlock)};

    xoodooState <= toChunks(nextState);
    /////////////////////////////

    /// send output on PT/CT
    case (recv_type)
      CT,PT: begin
        piso.enq(take(inputXorState), sipoValidLanes);
        outLastBlock <= inLastBlock;
      end
    endcase

  endrule

  (* fire_when_enabled *)
  rule rl_squeeze if (xState == Squeeze);
    piso.enq(take(concat(xoodooState)), fromInteger(crypto_abytes / 4) );
    
    if (secondSqueeze) begin // this was 1/2
      xoodooState[0][0][0] <=  xoodooState[0][0][0] ^ 1;
      xState <= Permute;
    end else begin
      outLastBlock  <= False;
      xState <= Absorb;
    end
    round_counter <= 0;

  endrule

  (* fire_when_enabled, no_implicit_conditions *)
  rule rl_permute if (xState == Permute);
    xoodooState <= round(xoodooState, round_counter);
    
    if (round_counter == fromInteger(valueOf(NumRounds) - 1) ) begin
      if(firstSqueeze && secondSqueeze) begin
        firstSqueeze  <= False;
        xState <= Squeeze;
      end else if (firstSqueeze || secondSqueeze) begin
        secondSqueeze <= False;
        xState <= Squeeze;
      end else
        xState <= Absorb;
    end else
      round_counter <= round_counter + 1;
  endrule

  (* fire_when_enabled *)
  rule rl_fill_zero if (inState == InFill && !sipo.isFull);
    zfilled <= True;
    fullAdBlock <= False;
    if(!zfilled)
      sipoValidLanes <= truncate(sipo.count);

    
    // replace key/1st HM, extend with zeros
    let replace = (recv_type == Key) || ((recv_type == HM) && inFirstBlock);
    sipoFlags.enq(replace ? 4'b1111 : 4'b0); 
    if (!zfilled && !last_word_padded) begin
      sipo.enq((recv_type == Key) ? 'h100 : 1);
    end
    else begin
      sipo.enq(0);
    end
  endrule

  function Bit#(4) padargToFlag(Bool lot, Bit#(2) padarg);
    return case(tuple2(lot, padarg)) matches
      {True, 2'd1} : 4'b0001;
      {True, 2'd2} : 4'b0011;
      {True, 2'd3} : 4'b0111;
      default      : 4'b1111;
    endcase;
  endfunction

  // ******************************** Methods and subinterfaces ********************************

  // typ:     SegmentType
  // empty:   input is empty
  method Action receive(SegmentType typ, Bool empty) if (inState == InIdle);
    recv_type        <=   typ;
    inFirstBlock     <=  True;
    inLastBlock      <= empty;
    zfilled          <= False;
    last_word_padded <= False;

    inState <= empty ? InFill : InRecv;
  endmethod

  interface FifoIn bdi;
    method Action enq(i) if ((inState == InRecv) && !sipo.isFull);
      match tagged BdIO {word: .word, lot: .lot, padarg: .padarg} = i;
      match {.padded, .pw} = padWord(word, padarg, True); 
      
      sipo.enq(lot ? pw : word);
      sipoFlags.enq(recv_type == HM ? 4'b1111 : padargToFlag(lot, padarg));

      let will_be_full = sipo.count == fromInteger(
          case(recv_type)
            HM, Key:  4;
            AD     : 11;
            default:  6;
          endcase - 1);

      if (lot || will_be_full) begin
        inState  <= InFill; // fill happens only if sipo not already full (i.e not AD full block)
        inPadarg <= padarg;
      end
      
      inLastBlock <= lot;
      fullAdBlock <= !(lot && padded) && will_be_full;
      last_word_padded <= lot && padded;

    endmethod
  endinterface

  interface FifoOut bdo;
    method deq = piso.deq;
    method first;
      let lot = outLastBlock && (piso.count == 1);
      return BdIO {word: piso.first, lot: lot, padarg: outPadarg} ;
    endmethod
    method notEmpty = piso.notEmpty;
  endinterface
  
endmodule : mkXoodyak

endpackage : Xoodyak