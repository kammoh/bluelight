package InputLayer;

import Vector :: *;
import CryptoCore :: *;
import BluelightUtils :: *;

import GiftRound :: *;

// TODO option to use shift-register for large block sizes?

function Bit#(4) padargToValids(Bool pad, PadArg padarg);
    return case(tuple2(pad, padarg)) matches
        {True, 2'd1} : 4'b0001;
        {True, 2'd2} : 4'b0011;
        {True, 2'd3} : 4'b0111;
        default      : 4'b1111;
    endcase;
endfunction

typedef TDiv#(GiftBlockBytes, 4) BlockWords;

// (* synthesize *)
module mkInputLayerNoExtraPad#(Byte cipherPadByte) (InputLayerIfc#(GiftBlockBytes));// provisos (Mul#(BlockWords, CoreWordBytes, n_bytes), Add#(a__, 4, n_bytes), Add#(c__, 32, TMul#(n_bytes, 8)));
    Reg#(Vector#(BlockWords, CoreWord)) block <- mkRegU;
    Reg#(Vector#(BlockWords, Bit#(CoreWordBytes))) valids <- mkRegU;
    Reg#( Bit#(TLog#(BlockWords))) counter <- mkReg(0);
    let closed <- mkReg(False);
    let needsPad <- mkReg(False); // only set with with closing word
    let full <- mkReg(False);
    Bool lastPlace = counter == fromInteger(valueOf(BlockWords) - 1);
    let do_deq <- mkPulseWireOR;
    let do_close <- mkPulseWireOR;
    let needs_pad_set <- mkPulseWireOR;
    let needs_pad_unset <- mkPulseWireOR;
    RWire#(Tuple2#(CoreWord, Bit#(CoreWordBytes))) enq_wire <- mkRWireSBR;

    let can_put = ((!closed && !full) || do_deq) && !needsPad;
    let can_get = (closed && !needsPad) || full;

    (* fire_when_enabled *)
    rule rl_enq_deq if (do_deq || isValid(enq_wire.wget));
        case (enq_wire.wget) matches 
            tagged Valid {.w, .v}: begin
                if (counter == 0 || do_deq) begin
                    block  <= unpack(zeroExtend(pack(w)));
                    valids <= unpack(zeroExtend(v));
                end else begin
                    block[counter] <= w;
                    valids[counter] <= v;
                end
                closed <= do_close;
                counter <= do_deq ? 1 : counter + 1;
            end
            tagged Invalid &&& do_deq: begin
                closed <= False;
                counter <= 0;
            end
        endcase
        full <= do_deq ? False : lastPlace; // if not do_deq, there was an enq!
    endrule

    (* fire_when_enabled *)
    rule rl_needspad if (needs_pad_set || needs_pad_unset);
        if (needs_pad_set)
            needsPad <= True;
        else
            needsPad <= False;
    endrule

    (* fire_when_enabled *)
    rule rl_pad if (!full && needsPad);
        enq_wire.wset(tuple2(unpack(zeroExtend(cipherPadByte)), 0));
        do_close.send();
        needs_pad_unset.send();
    endrule

    method Action put(CoreWord word, Bool last, Bool pad, PadArg padarg, Bool empty) if (can_put);
        match {.padded, .paddedWord} = padWord(pack(word), padarg, cipherPadByte);
        enq_wire.wset(tuple2(pad ? unpack(paddedWord) : word, empty ? 0 : padargToValids(pad, padarg)));
        if (last) begin
            do_close.send();
            if (pad && !padded && !lastPlace) needs_pad_set.send();
        end
    endmethod

    method ActionValue#(InLayerToCipher#(GiftBlockBytes)) get if (can_get);
        do_deq.send();
        return tuple2(unpack(pack(block)), unpack(pack(valids)));
    endmethod
endmodule

endpackage
