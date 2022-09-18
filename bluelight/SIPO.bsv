package SIPO;

import Vector         :: *;
import CryptoCore     :: *;
import BluelightUtils :: *;

interface SIPO#(numeric type num_words, type w__);
    method Action enq (w__ word, ValidBytes#(w__) byte_valids, Bool last);
    method Action deq ();
    (* always_ready *)
    method Vector#(num_words, w__) data;
    (* always_ready *)
    method Vector#(num_words, ValidBytes#(w__)) valids;
    (* always_ready *)
    method Bool oneShort;
    (* always_ready *)
    method Bool isFirstBlock;
    (* always_ready *)
    method Bool isLastBlock;
endinterface

// (* synthesize *)
module mkSIPO (SIPO#(num_words, w__)) provisos (Bits#(w__, w_bits__), Literal#(w__), Mul#(w_bytes__, 8, w_bits__));
    
    let      block <- mkRegU;
    let validBytes <- mkReg(replicate(0));
    let  lastBlock <- mkReg(False);
    let firstBlock <- mkReg(True);
    let      zFill <- mkReg(False);
    let do_deq     <- mkPulseWire;
    let enq_wire   <- mkRWireSBR;

    let is_full      = unpack(lsb(validBytes[0]));
    let is_one_short = unpack(lsb(validBytes[1])); // one short OR full
       
    // =================================================== Rules =================================================== //

    (* fire_when_enabled *)
    rule enq_deq if (do_deq || isValid(enq_wire.wget));
        case (enq_wire.wget) matches 
            tagged Valid {.last, .v, .w}: begin
                if (last) begin
                    lastBlock <= True;
                    if (!is_one_short || do_deq) zFill <= True;
                end else
                    if (do_deq) begin
                        zFill <= False;
                        lastBlock <= False;
                    end
                block <= shiftInAtN(block, w);
                if (do_deq) // single word will be in the block
                    validBytes <= shiftInAtN(replicate(0), v);
                else
                    validBytes <= shiftInAtN(validBytes, v);
            end
            tagged Invalid &&& do_deq: begin
                zFill      <= False;
                lastBlock  <= False;
                validBytes <= replicate(0);
            end
        endcase
        if (do_deq) firstBlock <= lastBlock;
    endrule

    (* fire_when_enabled *)
    rule zero_fill if (zFill && !is_full);
        enq_wire.wset(tuple3(False, 0, 0));
    endrule

    // ================================================= Interface ================================================= //

    method Action enq (w__ word, ValidBytes#(w__) byte_valids, Bool last) if (!zFill && (!is_full || do_deq)) =
        enq_wire.wset(tuple3(last, byte_valids, word));

    method Action deq if (is_full) = do_deq.send();

    method Vector#(num_words, w__) data = block;

    method Reg#(Vector#(num_words, ValidBytes#(w__))) valids = validBytes;

    method Bool isFirstBlock = firstBlock;

    method Bool isLastBlock = lastBlock;

    method Bool oneShort = is_one_short;

endmodule : mkSIPO

// interface SimpleSIPO#(numeric type num_words, type w__);
//     method Action enq (w__ word, Bool last);
//     method Action invalidate ();
//     method Vector#(num_words, w__) getData;
//     (* always_ready *)
//     method Bool full;
// endinterface

// module mkSimpleSIPO (SimpleSIPO#(num_words, w__)) provisos (Bits#(w__, w_bits__), Literal#(w__), Mul#(w_bytes__, 8, w_bits__), Add#(1, b__, w_bytes__));
//     let block       <- mkRegU;
//     let isFull      <- mkReg(False);
//     let setIsFull   <- mkPulseWire;
//     let unsetIsFull <- mkPulseWire;

//     (* fire_when_enabled *)
//     rule update_isfull if (setIsFull || unsetIsFull);
//         if (unsetIsFull) isFull <= False;
//         else if (setIsFull) isFull <= True;
//     endrule

//     method Action enq (w__ word, Bool last) if (!isFull);
//         block <= shiftInAtN(block, word);
//         if (last) setIsFull.send();
//     endmethod

//     method Action invalidate = unsetIsFull.send();

//     method Vector#(num_words, w__) getData if (isFull) = block;

//     method Bool full = isFull;

// endmodule : mkSimpleSIPO

endpackage : SIPO
