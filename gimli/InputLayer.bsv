package InputLayer;

import Vector :: *;
import CryptoCore :: *;
import Probe :: *;

// TODO try Mux based input fill as block size is small

typedef 4 BlockWords;
typedef 4 WordBytes;

// TODO repeated, move defs here?
typedef Vector#(WordBytes, Byte) Word;
typedef Vector#(BlockWords, Word) Block;
typedef Vector#(TMul#(BlockWords, WordBytes), Bool) ByteValids;

typedef Tuple2#(Block, ByteValids) OutType;
typedef Bit#(TLog#(TAdd#(BlockWords,1))) CountType;

interface InputLayerIfc;
    method Action put(Word word, Bool last, Bool pad, PadArg padarg, Bool empty);
    method ActionValue#(OutType) get;
    (* always_ready *)
    method Bool extraPad;
endinterface

function Bit#(4) padargToValids(Bool pad, PadArg padarg);
    return case(tuple2(pad, padarg)) matches
        {True, 2'd1} : 4'b0001;
        {True, 2'd2} : 4'b0011;
        {True, 2'd3} : 4'b0111;
        default      : 4'b1111;
    endcase;
endfunction

module mkInputLayer(InputLayerIfc);
    Reg#(Block) block <- mkRegU;
    Reg#(Vector#(BlockWords, Bit#(WordBytes))) valids <- mkRegU;
    Reg#(CountType) counter <- mkReg(0);
    let closed <- mkReg(False);
    let needsPad <- mkReg(False); // only set with with closing word
    Bool full = counter == fromInteger(valueOf(BlockWords));
    let do_deq <- mkPulseWireOR;
    let do_close <- mkPulseWireOR;
    let needs_pad_set <- mkPulseWireOR;
    let needs_pad_unset <- mkPulseWireOR;
    RWire#(Tuple2#(Word, Bit#(WordBytes))) enq_wire <- mkRWireSBR;

    let is_open = ((!closed && !full) ) && !needsPad;

    (* fire_when_enabled *)
    rule rl_enq_deq if (do_deq || isValid(enq_wire.wget));
        case (enq_wire.wget) matches 
            tagged Valid .enqued: begin
                match {.w, .v} = enqued;
                if (counter == 0 || do_deq) begin
                    block <= unpack(zeroExtend(pack(w)));
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
        enq_wire.wset(tuple2(unpack(zeroExtend(1'b1)), 0));
        do_close.send();
        needs_pad_unset.send();
    endrule


    method Action put(Word word, Bool last, Bool pad, PadArg padarg, Bool empty) if (((!closed && !full) || do_deq) && !needsPad);
        match {.padded, .paddedWord} = padWord(pack(word), padarg, True);
        enq_wire.wset(tuple2(pad ? unpack(paddedWord) : word, empty ? 0 : padargToValids(pad, padarg)));
        if (last) begin
            do_close.send();
            if (pad && !padded) needs_pad_set.send();
        end
    endmethod

    method ActionValue#(OutType) get if ((closed && !needsPad) || full);
        do_deq.send();
        return tuple2(block, unpack(pack(valids)));
    endmethod

    method Bool extraPad;
        return needsPad;
    endmethod
endmodule

endpackage
