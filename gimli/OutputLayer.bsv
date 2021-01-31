package OutputLayer;

import Vector :: *;
import CryptoCore :: *;

// TODO try Mux based input fill as blockVec size is small

typedef 4 BlockWords;
typedef 4 WordBytes;

function Byte enableByte(Bool valid, Byte b);
    return valid ? b : 0;
endfunction

// TODO repeated, move defs here?
typedef Vector#(WordBytes, Byte) Word;
typedef Vector#(BlockWords, Word) Block;
typedef Vector#(TMul#(BlockWords, WordBytes), Bool) ByteValids;

interface OutputLayerIfc;
    method Action enq(Block block, ByteValids valids);
    method Action deq;
    (* always_ready *)
    method Bool notEmpty;
    (* always_ready *)
    method CoreWord first;
    (* always_ready *)
    method Bool isLast;
endinterface

module mkOutputLayer(OutputLayerIfc);
    Reg#(Block) blockVec <- mkRegU;
    Reg#(Vector#(BlockWords, Bit#(WordBytes))) validsVec <- mkReg(replicate(0));
    let not_empty = unpack(|validsVec[0]);
    let last = not_empty && !unpack(|validsVec[1]);
    let do_deq <- mkPulseWire;
    RWire#(Tuple2#(Block, ByteValids)) enq_wire <- mkRWireSBR;

    (* fire_when_enabled *)
    rule rl_enq_deq if (do_deq || isValid(enq_wire.wget));
        case (enq_wire.wget) matches 
            tagged Valid .enqued: begin
                match {.b, .v} = enqued;
                blockVec <= b;
                validsVec <= unpack(pack(v));
            end
            tagged Invalid &&& do_deq: begin
                blockVec <= shiftInAtN(blockVec, Vector::last(blockVec));
                validsVec <= shiftInAtN(validsVec, 0);
            end
        endcase
    endrule

    method Action enq(Block block, ByteValids valids) if (!not_empty || (last && do_deq));
        enq_wire.wset(tuple2(block, valids));
    endmethod

    method Action deq if (not_empty);
        do_deq.send();
    endmethod

    method Bool notEmpty;
        return not_empty;
    endmethod

    method CoreWord first;
        return pack(zipWith(enableByte, unpack(validsVec[0]), blockVec[0]));
    endmethod

    method Bool isLast;
        return last;
    endmethod
endmodule

endpackage
