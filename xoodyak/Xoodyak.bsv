package Xoodyak;

import Vector::*;
import GetPut::*;

import XoodooDefs::*;
import SIPO::*;
import PISO::*;
import CryptoCore::*;

typedef XoodyakRounds NumRounds;

typedef enum {
  InIdle, // waiting on process command
  InBdi,  // recieve from bdi
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

  Reg#(UInt#(TLog#(TAdd#(MaxOutRateLanes, 1)))) sipoValidLanes <- mkRegU;

  Reg#(Bit#(2)) inPadarg  <- mkRegU;
  Reg#(Bit#(2)) outPadarg <- mkRegU;

  Reg#(Bit#(4)) udConstReg <- mkRegU;

  Reg#(Bool) zfilled <- mkRegU;
  Reg#(Bool) inFirstBlock    <- mkRegU;
  Reg#(Bool) inLastBlock     <- mkRegU; // last block of the segment
  Reg#(Bool) outLastBlock    <- mkRegU; // used only for lot to enable padding of bdo word
  Reg#(Bool) fullAdBlock     <- mkRegU;
  Reg#(Bool) enFirstSqueeze  <- mkReg(False);
  Reg#(Bool) enSecondSqueeze <- mkReg(False);

  // optimization:
  Reg#(Bool) replaceAllLanes <- mkRegU;
  Reg#(Bool) replaceLowerLanes <- mkRegU;

  let squeeze = enFirstSqueeze || enSecondSqueeze;

  let inRecvKey = inRecvType == Key;
  let inRecvAD  = inRecvType == AD;

  let sipoCount = sipo.count;
  let sipoCountReached3  = pack(sipoCount)[1:0] == 3;
  let sipoCountReached5  = pack(sipoCount)[2] == 1 && pack(sipoCount)[0] == 1;
  let sipoCountReached10 = pack(sipoCount)[3] == 1 && pack(sipoCount)[1] == 1;

  function Tuple2#(Vector#(12, XoodooLane),Vector#(MaxOutRateLanes, XoodooLane)) absorbNextAndOut;
    let currentState = concat(xoodooState);
    Vector#(11, XoodooLane) inputXorState = toChunks(pack(sipo.data) ^ pack(init(currentState)));
    Vector#(12, XoodooLane) nextState;
    Integer i;
    for (i=0; i<6; i=i+1) begin
      let d = sipo.data[i];
      let x = inputXorState[i];
      let lane = case (sipoFlags.data[i])
        4'b0001 : {x[31: 8], d[7 :0]};
        4'b0011 : {x[31:16], d[15:0]};
        4'b0111 : {x[31:24], d[23:0]};
        4'b1111 : d;
        default : x;
      endcase;
      nextState[i] = replaceLowerLanes ? lane : x;
    end
    for (i=6; i<11; i=i+1) begin
      nextState[i] = replaceAllLanes ? 0 : inputXorState[i];
    end
    XoodooLane lastLane = replaceAllLanes ? 0 : last(currentState);
    nextState[11] = {lastLane[31:24] ^ {udConstReg[3:2], 4'b0, udConstReg[1:0]} , lastLane[23:1], lastLane[0] ^ pack(fullAdBlock)};
    
    return tuple2(nextState, squeeze ? take(currentState) : take(inputXorState));
  endfunction

  // either absorb, absorb+squeeze or just squeeze
  (* fire_when_enabled *)
  rule rl_absorb_squeeze if (inState == InFull && xState == Absorb && !piso.notEmpty); // TODO decouple piso
    udConstReg      <= 0; // 0 if squeeze
    fullAdBlock     <= False;
    inFirstBlock    <= False;
    inLastBlock     <= False;
    zfilled         <= False;
    lastWordPadded  <= False;
    replaceAllLanes <= False;
    if (replaceAllLanes) // HashMessage!
      replaceLowerLanes <= False;
    
    if (!squeeze) begin
      outLastBlock <= inLastBlock; // bdo.lot to pad output
      if (inLastBlock) begin
        case (inRecvType)
          Plaintext, Ciphertext: begin
            enFirstSqueeze <= True;
            sipoValidLanes <= 4;
          end
          HashMessage: begin
            enFirstSqueeze  <= True;
            enSecondSqueeze <= True;
            sipoValidLanes <= 4;
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
    
    if (!enFirstSqueeze && enSecondSqueeze)
      enSecondSqueeze <= False;

    match {.nextState, .outBytes} = absorbNextAndOut;
    if (enFirstSqueeze == enSecondSqueeze) // either !squeeze or hash:firstSqueeze
      xoodooState <= toChunks(nextState);

    /// send output
    outPadarg <= squeeze ? 0 : inPadarg;
    if (inRecvType == Ciphertext || inRecvType == Plaintext || squeeze) begin
        piso.enq(outBytes, sipoValidLanes);
    end
        
    // always permute after absorb/squeeze
    roundCounter <= 0;
    xState <= Permute;
  endrule

  /// Permutation Rounds ///
  (* fire_when_enabled, no_implicit_conditions *)
  rule rl_permute if (xState == Permute);
    if (roundCounter == fromInteger(valueOf(NumRounds) - 1))
      xState <= Absorb;
    xoodooState <= round(xoodooState, roundCounter);
    roundCounter <= roundCounter + 1;
  endrule

  (* fire_when_enabled *)
  rule rl_fill_zero if (inState == InZeroFill);
    zfilled <= True;
    fullAdBlock <= False;
    if(!zfilled && !enSecondSqueeze)
      sipoValidLanes <= truncate(sipoCount);
    // replace state with key or 1st HashMessage block, extended with zeros
    sipoFlags.enq(replaceAllLanes ? 4'b1111 : 4'b0); 
    if (!zfilled && !lastWordPadded) begin
      sipo.enq(inRecvKey ? 'h100 : 1);
    end
    else begin
      sipo.enq(0);
    end

    if (sipoCountReached10)
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
    zfilled         <= False;
    fullAdBlock    <= False;
    lastWordPadded <= False;
    udConstReg     <= udConstBits(True, empty, typ);
    inState <= empty ? InZeroFill : InBdi;

    replaceAllLanes   <= typ == Key || typ == HashMessage;
    replaceLowerLanes <= typ == Key || typ == HashMessage || typ == Ciphertext;
  endmethod
  
  interface FifoIn bdi;
    method Action enq(i) if (inState == InBdi);
      match tagged BdIO {word: .word, lot: .lot, padarg: .padarg} = i;
      match {.padded, .pw} = padWord(word, padarg, True); 
      
      sipo.enq(lot ? pw : word);
      sipoFlags.enq(replaceAllLanes ? 4'b1111 : padargToFlag(lot, padarg));

      let lastWordOfBlock =
          case(inRecvType)
            HashMessage: sipoCountReached3;
            default: sipoCountReached5;
          endcase;

      if (inRecvAD) begin
        if (sipoCountReached10) begin
          inState <= InFull;
          fullAdBlock <= !(lot && padded);
        end else if (lot)
          inState  <= InZeroFill;
      end else if (lot || lastWordOfBlock)
        inState  <= InZeroFill; // fill happens only if sipo not already full (i.e not AD full block)

      inPadarg <= padarg;
      inLastBlock <= lot;
      lastWordPadded <= lot && padded;

      udConstReg <= udConstBits(inFirstBlock, lot, inRecvType);
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
