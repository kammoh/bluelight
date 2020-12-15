package Xoodyak;

import Vector::*;
import GetPut::*;

import XoodooDefs::*;
import SIPO::*;
import PISO::*;
import CryptoCore::*;

typedef enum {
  InIdle, // waiting to process command
  InBdi, // recieve from bdi
  InZeroFill,
  InFull
} InputState deriving(Bits, Eq);

typedef enum {
  Absorb,
  Permute
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

  Reg#(UInt#(TLog#(NumRounds))) roundCounter <- mkRegU;

  Reg#(SegmentType) inRecvType <- mkRegU;
  Reg#(Bool) lastWordPadded <- mkRegU;

  Reg#(UInt#(TLog#(7))) sipoValidLanes <- mkRegU;

  Reg#(Bit#(2)) inPadarg  <- mkRegU;
  Reg#(Bit#(2)) outPadarg <- mkRegU;

  Reg#(Bool) zfilled <- mkRegU;
  Reg#(Bool) inFirstBlock  <- mkRegU;
  Reg#(Bool) inLastBlock   <- mkRegU; // last block of the segment
  Reg#(Bool) outLastBlock  <- mkReg(False); // used only for lot to enable padding of bdo word
  Reg#(Bool) fullAdBlock   <- mkRegU;
  Reg#(Bool) enFirstSqueeze  <- mkReg(False);
  Reg#(Bool) enSecondSqueeze <- mkReg(False);

  let squeeze = enFirstSqueeze || enSecondSqueeze;

  let inRecvHM  = inRecvType == HM;
  let inRecvKey = inRecvType == Key;
  let inRecvAD = inRecvType == AD;
  let inRecvHMorKey = inRecvHM || inRecvKey;

  function Byte udConst();
    return case (inRecvType)
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

  // either absorb, absorb+squeeze or just squeeze
  (* fire_when_enabled *)
  rule rl_absorb_squeeze if (inState == InFull && xState == Absorb && !piso.notEmpty); // TODO decouple piso
    
    // TODO move out
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
      nextState[i] = case (inRecvType)
        Key, CT: lane; // replace flagged bytes
        HM : (inFirstBlock ? lane : x);
        default : x;
      endcase;
    end
    XoodooLane lastLane = (inRecvKey || (inRecvHM && inFirstBlock)) ? 0 : last(currentState);
    nextState[11] = {lastLane[31:24] ^ udConst, lastLane[23:1], lastLane[0] ^ pack(fullAdBlock)};
    //END OF MOVE OUT

    fullAdBlock    <= False;
    inFirstBlock   <= False;
    inLastBlock    <= False;
    zfilled        <= False;
    lastWordPadded <= False;
    
    if (!squeeze) begin

      outLastBlock <= inLastBlock; // bdo.lot to pad output

      if (inLastBlock) begin
        case (inRecvType)
          PT, CT:
            enFirstSqueeze  <= True;
          HM: begin
            enFirstSqueeze  <= True;
            enSecondSqueeze <= True;
            sipo.deq;
            inState <= InZeroFill;
          end
          default: begin
            sipo.deq;
            inState <= InIdle;
          end
        endcase
      end else begin
        sipo.deq;
        inState <= InBdi; // get more bdi
      end
    end else begin
      enFirstSqueeze  <= False;
      
      if (!(enFirstSqueeze && enSecondSqueeze)) begin
        sipo.deq;
        inState <= InIdle;
      end
    end
    
    if (!enFirstSqueeze && enSecondSqueeze) enSecondSqueeze <= False;

    if (enFirstSqueeze == enSecondSqueeze) // either ! squeeze of hash firstSqueeze
      xoodooState <= toChunks(nextState);


    /////////////////////////////

    /// send output
    outPadarg <= squeeze ? 0 : inPadarg;
    if (inRecvType == CT || inRecvType == PT || squeeze) begin
        piso.enq(squeeze ? take(currentState) : take(inputXorState), squeeze ? 4 : sipoValidLanes);
    end
        
    // always permute after absorb/squeeze
    roundCounter <= 0;
    xState <= Permute;
  endrule

  // (* fire_when_enabled *)
  // rule rl_squeeze if (xState == Squeeze);
  //   piso.enq(take(concat(xoodooState)), fromInteger(crypto_abytes / 4) );
    
  //   if (enSecondSqueeze) begin // this was 1/2
  //     xoodooState[0][0][0] <=  xoodooState[0][0][0] ^ 1;
  //     xState <= Permute;
  //   end else begin
  //     outLastBlock  <= False;
  //     xState <= Absorb;
  //   end
  //   roundCounter <= 0;

  // endrule

  /// Permutation Rounds ///
  (* fire_when_enabled, no_implicit_conditions *)
  rule rl_permute if (xState == Permute);
    xoodooState <= round(xoodooState, roundCounter);
    
    if (roundCounter == fromInteger(valueOf(NumRounds) - 1) )
      xState <= Absorb;
    //   if(enFirstSqueeze && enSecondSqueeze) begin
    //     enFirstSqueeze  <= False;
    //     xState <= Squeeze;
    //   end else if (enFirstSqueeze || enSecondSqueeze) begin
    //     enSecondSqueeze <= False;
    //     xState <= Squeeze;
    //   end else
    //     xState <= Absorb;
    // end else
      roundCounter <= roundCounter + 1;
  endrule

  let sipoWillFill = sipo.count == 10;
  // let sipoWillFill =  (sipo.count[3] == 1 && sipo.count[1] == 1) // 11 - 1

  (* fire_when_enabled *)
  rule rl_fill_zero if (inState == InZeroFill && !sipo.isFull);
    zfilled <= True;
    fullAdBlock <= False;
    if(!zfilled)
      sipoValidLanes <= truncate(sipo.count);
    
    // replace state with key or 1st HM block, extended with zeros
    let replace = inRecvKey || (inRecvHM && inFirstBlock);
    sipoFlags.enq(replace ? 4'b1111 : 4'b0); 
    if (!zfilled && !lastWordPadded) begin
      sipo.enq(inRecvKey ? 'h100 : 1);
    end
    else begin
      sipo.enq(0);
    end

    if (sipoWillFill)
      inState <= InFull;
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
  method Action process(SegmentType typ, Bool empty) if (inState == InIdle);
    inRecvType     <=   typ;
    inFirstBlock   <=  True;
    inLastBlock    <= empty;
    zfilled        <= False;
    fullAdBlock    <= False;
    lastWordPadded <= False;

    inState <= empty ? InZeroFill : InBdi;
  endmethod
  
  interface FifoIn bdi;
    method Action enq(i) if ((inState == InBdi) && !sipo.isFull);
      match tagged BdIO {word: .word, lot: .lot, padarg: .padarg} = i;
      match {.padded, .pw} = padWord(word, padarg, True); 
      
      sipo.enq(lot ? pw : word);
      sipoFlags.enq(inRecvHM ? 4'b1111 : padargToFlag(lot, padarg));

      let lastWordOfBlock =
          case(inRecvType)
            // HM, Key: sipo.count[1:0] == 2'b11; // 4 - 1
            HM, Key: (sipo.count == 3); // 4 - 1
            // default: sipo.count[2] == 1 && sipo.count[0] == 1; // 6 - 1
            default: (sipo.count == 5); // 6 - 1
          endcase;

      if (inRecvAD) begin
        if (sipoWillFill) begin
          inState <= InFull;
          fullAdBlock <= !(lot && padded);
          sipoValidLanes <= truncate(sipo.count);
        end else if (lot)
          inState  <= InZeroFill;
      end else if (lot || lastWordOfBlock)
          inState  <= InZeroFill; // fill happens only if sipo not already full (i.e not AD full block)

      inPadarg <= padarg;
      inLastBlock <= lot;
      lastWordPadded <= lot && padded;
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