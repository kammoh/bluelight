package InputLayer;

import Vector :: *;
import Probe :: *;

import CryptoCore :: *;
import BluelightUtils :: *;

typedef struct  {
    Bool last;
    ByteValidsOfSize#(n_bytes) valid_bytes;
    BlockOfSize#(n_bytes) data;
} InputBlock#(numeric type n_bytes) deriving (FShow, Bits);

interface InputLayerIfc#(numeric type n_out_bytes);
    method Action put(CoreWord data, ValidBytes#(CoreWord) valid_bytes, Bool last);
    method ActionValue#(InputBlock#(n_out_bytes)) get;
endinterface

typedef 4 CoreWordBytes;

module mkInputLayer#(Byte cipherPadByte) (InputLayerIfc#(n_out_bytes)) 
provisos (
    Mul#(block_words, CoreWordBytes, n_out_bytes),
    Add#(a__, 4, n_out_bytes), // n_out_bytes >= 4
    Add#(b__, 32, TMul#(block_words, 32)), // block_words >= 1
    Add#(c__, 32, TMul#(n_out_bytes, 8))
);
    //==== Registers ====//
    Reg#(Vector#(block_words, CoreWord)) block <- mkRegU;
    Reg#(Vector#(block_words, Bit#(CoreWordBytes))) valids <- mkRegU;
    Reg#(Bit#(TLog#(TAdd#(block_words, 1)))) counter <- mkReg(0);
    // Reg#(Bool) isLast   <- mkRegU;
    Reg#(Bool) closed   <- mkReg(False);
    Reg#(Bool) needsPad <- mkReg(False); // only set with with closing word
    
    //===== Wires =====//
    Bool full = counter == fromInteger(valueOf(block_words));
    let do_deq <- mkPulseWireOR;
    let do_close <- mkPulseWireOR;
    // let needs_pad_set <- mkPulseWireOR;
    // let needs_pad_unset <- mkPulseWireOR;
    RWire#(Tuple2#(CoreWord, Bit#(CoreWordBytes))) enq_wire <- mkRWireSBR;

    let put_probe_data <- mkProbe();
    let put_probe_valids <- mkProbe();
    let put_probe_last <- mkProbe();

    (* fire_when_enabled *)
    rule rl_enq_deq if (do_deq || isValid(enq_wire.wget));
        case (enq_wire.wget) matches 
            tagged Valid .enqued: begin
                match {.w, .v} = enqued;
                if (counter == 0 || do_deq) begin
                    block <= unpack(zeroExtend(pack(w))); // do we need to zero fill the whole block?
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

    // (* fire_when_enabled *)
    // rule rl_needspad if (needs_pad_set || needs_pad_unset);
    //     if (needs_pad_set)
    //         needsPad <= True;
    //     else
    //         needsPad <= False;
    // endrule

    (* fire_when_enabled *)
    rule rl_pad if (!full && needsPad);
        enq_wire.wset(tuple2(unpack(zeroExtend(cipherPadByte)), 0));
        do_close.send();
        // needs_pad_unset.send();
        needsPad <= False;
    endrule

    //======================================== Interface ========================================//
    method Action put (CoreWord word, ValidBytes#(CoreWord) valid_bytes, Bool last) if (((!closed && !full) || do_deq) && !needsPad);
        put_probe_data <= word;
        put_probe_valids <= valid_bytes;
        put_probe_last <= last;

        let padded           = valid_bytes[3] == 0;
        let empty            = valid_bytes[0] == 0;

        let paddedWord = padInWord(pack(word), valid_bytes, cipherPadByte);
        enq_wire.wset(tuple2(pack(paddedWord), valid_bytes));

        // isLast <= last;
        if (last) begin
            do_close.send();
            if (!padded)
                needsPad <= True;
                // needs_pad_set.send();
        end
    endmethod

    method ActionValue#(InputBlock#(n_out_bytes)) get if ((closed && !needsPad) || full);
        do_deq.send();
        return InputBlock{data: unpack(pack(block)), valid_bytes: unpack(pack(valids)), last: closed && !needsPad };
    endmethod
endmodule

endpackage
