package BusFIFO;

import BusDefines   :: *;
import FIFO         :: *;
import FIFOF        :: *;
import SpecialFIFOs :: *;


// pipelined
module mkBusSender (BusSender#(a)) provisos (Bits#(a, sa__));
    let data_valid <- mkReg(False);
    let data_reg   <- mkRegU;
    let do_enq     <- mkPulseWire;
    let do_deq     <- mkPulseWire;

    (* fire_when_enabled, no_implicit_conditions *)
    rule enq_deq if (do_enq || do_deq);
        data_valid <= do_enq;
    endrule

    method Action put(a data) if (!data_valid || do_deq);
        data_reg <= data;
        do_enq.send;
    endmethod

    interface BusSend out;
        method a data;
            return data_reg;
        endmethod
        method Bool valid;
            return data_valid;
        endmethod
        method Action ready(Bool value);
            if (value) do_deq.send;
        endmethod
    endinterface
endmodule

// pipelined
module mkBusReceiver (BusReceiver#(a)) provisos(Bits#(a, sa));
    let fifof     <- mkPipelineFIFOF;
    let data_wire <- mkBypassWire;
    let enq_valid <- mkPulseWire;
    let deq_pw    <- mkPulseWire;

    rule do_enq (enq_valid);
        fifof.enq(data_wire);
    endrule

    interface BusRecv in;
        method Action data(a value);
            data_wire <= value;
        endmethod
        method Action valid(Bool value);
            if (value) enq_valid.send;
        endmethod
        method Bool ready;
            return (fifof.notFull || deq_pw);
        endmethod
    endinterface

    method ActionValue#(a) get;
        deq_pw.send;
        fifof.deq;
        return fifof.first;
    endmethod
endmodule


endpackage
