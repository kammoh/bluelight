package PISO;

import Vector         :: *;
import CryptoCore     :: *;
import BluelightUtils :: *;

interface PISO#(numeric type num_words, type w__);
    method Action enq(Vector#(num_words, w__) data, Vector#(num_words, ValidBytes#(w__)) valids);
    method Action deq;
    (* always_ready *)
    method Bool notEmpty;
    (* always_ready *)
    method w__ first;
    (* always_ready *)
    method Bool isLast;
endinterface

module mkPISO (PISO#(num_words, w__)) provisos (Bits#(w__, w_bits__), Mul#(w_bytes__, 8, w_bits__), 
        Div#(w_bits__, 8, w_bytes__), Add#(1, b__, num_words));

    let blockVec  <- mkRegU;
    let validsVec <- mkReg(replicate(0));
    let do_deq    <- mkPulseWire;
    let enq_wire  <- mkRWireSBR;

    let not_empty = unpack(lsb(validsVec[0]));
    let last = not_empty && !unpack(lsb(validsVec[1]));

    // =================================================== Rules =================================================== //

    (* fire_when_enabled *)
    rule rl_enq_deq if (do_deq || isValid(enq_wire.wget));
        case (enq_wire.wget) matches 
            tagged Valid .enqued: begin
                match {.b, .v} = enqued;
                blockVec  <= b;
                validsVec <= v;
            end
            tagged Invalid &&& do_deq: begin
                blockVec <= shiftInAtN(blockVec, Vector::last(blockVec));
                validsVec <= shiftInAtN(validsVec, 0);
            end
        endcase
    endrule

    // ================================================= Interface ================================================= //

    method Action enq(Vector#(num_words, w__) data, Vector#(num_words, ValidBytes#(w__)) valids)
            if (!not_empty || (last && do_deq)) = enq_wire.wset(tuple2(data, valids));

    method Action deq if (not_empty) = do_deq.send();

    method Bool notEmpty = not_empty;

    method w__ first = padOutWord (blockVec[0], validsVec[0]);

    method Bool isLast = last;

endmodule : mkPISO

endpackage : PISO
