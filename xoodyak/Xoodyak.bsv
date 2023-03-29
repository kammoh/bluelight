package Xoodyak;

import Vector :: *;
import GetPut :: *;
import Assert :: *;

import XoodooDefs :: *;
import SIPO       :: *;
import PISO       :: *;
import CryptoCore :: *;

typedef XoodyakRounds NumRounds;

typedef enum {
    S_Idle,
    S_ReceiveKey,
    S_ReceiveData,
    S_ZeroFill,
    S_Hash2AddOne
} InputState deriving(Bits, Eq);

typedef enum {
    SO_Absorb,
    SO_Permutate,
    SO_SqueezeH0,
    SO_Squeeze
} OperatingState deriving(Bits, Eq);

function Byte select_byte(Bool v, Byte di, Byte xi) = v ? di : xi;

(* default_clock_osc="clk", default_reset="rst" *)
`ifdef DEBUG
(* synthesize *)
`endif
module mkXoodyak(CryptoCoreIfc#(32)) provisos (NumAlias#(w__, 32));
    SIPO#(MaxInRateLanes, XoodooLane) sipo <- mkSIPO(False);
    PISO#(MaxOutRateLanes, XoodooLane) piso <- mkPISO;

    // 1 bit for each byte in every the input SIPO lane
    MyShiftReg#(MaxInRateLanes, Bit#(4)) valid_bytes_sr <- mkMyShiftReg;

    // FSMs
    let in_state <- mkReg(S_Idle); // input in_state
    let op_state <- mkReg(SO_Absorb);

    Reg#(XoodooState) xoodooState              <- mkRegU;
    Reg#(UInt#(TLog#(NumRounds))) roundCounter <- mkRegU;
    Reg#(UInt#(TLog#(TAdd#(2, 1)))) squeezes   <- mkRegU;
    Reg#(Bit#(4)) udConst                      <- mkRegU;
    Reg#(Bit#(4)) in_valid_bytes               <- mkRegU;
    Reg#(Bit#(4)) out_last_valid_bytes         <- mkRegU;
    let valid_words                            <- mkRegU;

    Reg#(Bool) inKey           <- mkRegU;
    Reg#(Bool) inPtCt          <- mkRegU;
    Reg#(Bool) inHm            <- mkRegU;
    Reg#(Bool) in_eoi          <- mkRegU;
    Reg#(Bool) lastWordPadded  <- mkRegU;
    Reg#(Bool) zfilled         <- mkRegU;
    Reg#(Bool) hash_extra_add1 <- mkRegU;
    Reg#(Bool) first_block     <- mkRegU; // first block of a type
    Reg#(Bool) fullAdBlock     <- mkRegU;
    Reg#(Bool) replace_high    <- mkRegU;

    // one before last element
    let sipo_almost_full = sipo.guage[9];
    // input ^ state
    Vector#(11, XoodooLane) inputXorState = toChunks(pack(sipo.data) ^ pack(init(concat(xoodooState))));
    // absorbed state
    Vector#(12, XoodooLane) absState = reverse(cons(last(concat(xoodooState)), reverse(inputXorState)));

    for (Integer i=0; i<6; i=i+1)
        absState[i] = pack(zipWith3(select_byte,
            unpack(valid_bytes_sr.data[i]), toChunks(sipo.data[i]), toChunks(inputXorState[i])));

    if (replace_high)
        begin
            for (Integer i=6; i<11; i=i+1)
                absState[i] = sipo.data[i];
            absState[11] = 0;
        end

    absState[11][31:30] = absState[11][31:30] ^ udConst[3:2];
    absState[11][25:24] = absState[11][25:24] ^ udConst[1:0];
    absState[11][0]     = absState[11][0]     ^ pack(fullAdBlock);

    /// Only absorb ///
    (* fire_when_enabled *)
    rule absorb if (op_state == SO_Absorb && !inPtCt);
        sipo.deq;
        squeezes     <= (in_eoi && inHm) ? 2 : 0;
        xoodooState  <= toChunks(absState);
        roundCounter <= 0;
        op_state     <= SO_Permutate;
    endrule

    /// Absorb + Squeeze ///
    (* fire_when_enabled *)
    rule absorb_and_squeeze if (op_state == SO_Absorb && inPtCt);
        sipo.deq;
        piso.enq(WithLast{data: take(inputXorState), last: in_eoi}, valid_words);
        squeezes             <= in_eoi ? 1 : 0;
        xoodooState          <= toChunks(absState);
        out_last_valid_bytes <= in_valid_bytes;
        roundCounter         <= 0;
        op_state             <= SO_Permutate;
    endrule

    /// Only squeeze ///
    (* fire_when_enabled *)
    rule final_squeeze if (op_state == SO_Squeeze);
        piso.enq(WithLast{data: take(concat(xoodooState)), last: True}, unpack('hf));
        out_last_valid_bytes <= 'hf;
        op_state             <= SO_Absorb;
    endrule

    /// Hash first squeeze ///
    (* fire_when_enabled *)
    rule squeeze_h0 if (op_state == SO_SqueezeH0);
        sipo.deq;
        piso.enq(WithLast{data: take(concat(xoodooState)), last: False}, unpack('hf));
        xoodooState          <= toChunks(absState);
        out_last_valid_bytes <= 'hf;
        squeezes             <= 1;
        roundCounter         <= 0;
        op_state             <= SO_Permutate;
    endrule

    /// Permutation Rounds ///
    (* fire_when_enabled, no_implicit_conditions *)
    rule permutate if (op_state == SO_Permutate);
        if (roundCounter == fromInteger(valueOf(NumRounds) - 1))
            op_state <= (squeezes == 0) ? SO_Absorb : (squeezes == 2) ? SO_SqueezeH0 : SO_Squeeze;
        xoodooState <= round(xoodooState, roundCounter);
        roundCounter <= roundCounter + 1;
    endrule

    /// Fill-in SIPO with zeros or padding ///
    (* fire_when_enabled *)
    rule fill_zero if (in_state == S_ZeroFill);
    `ifdef ROUND2
        let kf = 'h01_00;
    `else
        let kf = 'h01_10;
    `endif
        sipo.enq((!zfilled && !lastWordPadded) ? (inKey ? kf : 1) : 0);
        // replace in_state with key or 1st HashMessage block, extended with zeros
        valid_bytes_sr.enq(replace_high ? 'hf : 0);
        fullAdBlock <= False;
        zfilled     <= True;
        if (!zfilled)
            valid_words <= take(sipo.guage);
        if (sipo_almost_full)
            if (!hash_extra_add1)
                in_state <= in_eoi ? S_Idle : S_ReceiveData;
            else
                in_state <= S_Hash2AddOne;
    endrule

    /// Hash: Absorb 0x1 (in the SIPO) after the first squeeze ///
    (* fire_when_enabled *)
    rule second_digest_add_one if (in_state == S_Hash2AddOne);
        sipo.enq(1);
        valid_bytes_sr.enq(0);
        hash_extra_add1 <= False;
        replace_high    <= False;
        udConst         <= 0;
        in_state        <= S_ZeroFill;
    endrule

    // ******************************* Methods and subinterfaces **********************************
    /// Start a new operation ///
    method Action start (Bool new_key, Bool decrypt, Bool hash) if (in_state == S_Idle);
    `ifdef DEBUG
        dynamicAssert(new_key, "Key reuse is not supported!");
    `endif
        // any registers changed here can ONLY be used in data() or key() methods
        first_block <= True;
        in_state <= hash ? S_ReceiveData : S_ReceiveKey;
    endmethod

    // Receive AEAD Key ///
    method Action key_in (Bit#(w__) data, Bool last) if (in_state == S_ReceiveKey);
        sipo.enq(data);
        valid_bytes_sr.enq('hf);
    `ifdef ROUND2
        inKey           <= True;
        inPtCt          <= False;
        inHm            <= False;
        in_eoi          <= False;
        zfilled         <= False;
        fullAdBlock     <= False;
        lastWordPadded  <= False;
        hash_extra_add1 <= False;
        replace_high    <= True;
        in_valid_bytes  <= 4;
        udConst         <= 4'b0010;
        if (last)
            in_state <= S_ZeroFill;
    `else
        if (last)
            in_state <= S_ReceiveData;
    `endif
    endmethod

    /// Receive data ///
    method Action data_in (Bit#(w__) data, Bit#(TDiv#(w__, 8)) valid_bytes, Bit#(TDiv#(w__, 8)) pad_loc, Bool last, HeaderFlags flags) if (in_state == S_ReceiveData);
        let padded           = valid_bytes[3] == 0;
        let empty            = valid_bytes[0] == 0;
        let first_hm         = flags.hm && first_block;
        
        sipo.enq(pad10(data, pad_loc));
        lastWordPadded  <= last && padded;
    `ifdef ROUND2
        let full_short_block = (flags.hm && sipo.guage[2]) || (!flags.ad && sipo.guage[4]);
        inKey <= False;
        valid_bytes_sr.enq(first_hm ? 'hf : flags.ct ? valid_bytes : 0);
    `else
        let full_short_block = (flags.hm && sipo.guage[2]) || (!flags.ad && !flags.npub && sipo.guage[4]) || (flags.npub && sipo.guage[6]);
        inKey <= flags.npub;
        valid_bytes_sr.enq((first_hm || flags.npub) ? 'hf : flags.ct ? valid_bytes : 0);
    `endif
        inPtCt          <= flags.ptct;
        inHm            <= flags.hm;
        in_eoi          <= last && flags.end_of_input;
        zfilled         <= empty;
        fullAdBlock     <= sipo_almost_full && !padded;
        in_valid_bytes  <= valid_bytes;
        hash_extra_add1 <= last && flags.hm;
    `ifdef ROUND2
        replace_high    <= first_hm;
    `else
        replace_high    <= first_hm || flags.npub;
    `endif
        valid_words     <= replicate(False);

        if (last)
            first_block <= True;
        else if (full_short_block || sipo_almost_full)
            first_block <= False;
        udConst <=
            case ({pack(flags.npub), pack(flags.ad), pack(flags.ptct)}) matches
            `ifdef ROUND2
                'b1??   : 4'b0011;
            `else
                'b1??   : 4'b0010; // NPUB is absorbed as Key
            `endif
                'b?1?   : {pack(last), 1'b0, pack(first_block), pack(first_block)};
                'b??1   : {1'b0, pack(last), 2'b0};
                default : {3'b0, pack(first_block)};
            endcase;
        if ((last && !sipo_almost_full) || full_short_block)
            in_state <= S_ZeroFill;
    endmethod


    interface FifoOut data_out;
        method deq = piso.deq;
        method first;
            return WithLast {
                data: clear_invalid_bytes_cond(piso.first.data, out_last_valid_bytes, piso.first.last),
                last: piso.first.last
            };
        endmethod
        method notEmpty = piso.notEmpty;
    endinterface
endmodule

endpackage
