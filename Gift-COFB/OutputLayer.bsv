package OutputLayer;

import Vector :: *;
import CryptoCore :: *;
import BluelightUtils :: *;

// TODO try Mux based input fill as blockVec size is small

function Byte enableByte(Bool valid, Byte b);
    return valid ? b : 0;
endfunction

module mkOutputLayer(OutputLayerIfc#(n_bytes)) provisos (Mul#(block_words, CoreWordBytes, n_bytes), Add#(a__, 4, n_bytes), Add#(1, b__, block_words), Add#(c__, 32, TMul#(n_bytes, 8)));
    Reg#(Vector#(block_words, CoreWord)) blockVec <- mkRegU;
    Reg#(Vector#(block_words, Bit#(CoreWordBytes))) validsVec <- mkReg(replicate(0));
    let not_empty = unpack(|validsVec[0]);
    let last = not_empty && !unpack(|validsVec[1]);
    let do_deq <- mkPulseWire;
    RWire#(Tuple2#(BlockOfSize#(n_bytes), ByteValidsOfSize#(n_bytes))) enq_wire <- mkRWireSBR;

    (* fire_when_enabled *)
    rule rl_enq_deq if (do_deq || isValid(enq_wire.wget));
        case (enq_wire.wget) matches 
            tagged Valid .enqued: begin
                match {.b, .v} = enqued;
                blockVec <= unpack(pack(b));
                validsVec <= unpack(pack(v));
            end
            tagged Invalid &&& do_deq: begin
                blockVec <= shiftInAtN(blockVec, Vector::last(blockVec));
                validsVec <= shiftInAtN(validsVec, 0);
            end
        endcase
    endrule

    method Action enq(BlockOfSize#(n_bytes) block, ByteValidsOfSize#(n_bytes) valids) if (!not_empty || (last && do_deq));
        enq_wire.wset(tuple2(block, valids));
    endmethod

    method Action deq if (not_empty);
        do_deq.send();
    endmethod

    method Bool notEmpty;
        return not_empty;
    endmethod

    method CoreWord first;
        return pack( zipWith(enableByte, unpack(validsVec[0]), unpack(blockVec[0])) );
    endmethod

    method Bool isLast;
        return last;
    endmethod
endmodule

endpackage
