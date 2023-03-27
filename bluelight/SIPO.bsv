package SIPO;

import Vector::*;
import PISO::*;

export SIPO::*;
export Vector::*;

interface SIPO #(numeric type size, type el_type);
  method Action enq(el_type in_data); 
  method Action deq;
  (* always_ready *)
  method Vector#(size, el_type) data;
  (* always_ready *)
  method Vector#(size, Bool) guage;
  (* always_ready *)
  method Bool isFull;
endinterface

// SIPO (Serial In, Parallel Out)
//    pipelined:   when full, enq can happen simultaneously with deq of first element
(* default_clock_osc="clk" *)
(* default_reset="rst" *)
module mkSIPO#(Bool pipelined) (SIPO#(size, el_type)) provisos (Bits#(el_type, width),  Add#(1, a__, size));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;
  Reg#(Vector#(size, Bool)) filled <- mkReg(replicate(False));

  let do_enq <- mkPulseWire();
  let do_deq <- mkPulseWire();

  Bool full = last(filled);
  Bool can_enq = pipelined ? (!full || do_deq) : !full;
  
  (* fire_when_enabled, no_implicit_conditions *)
  rule rl_update_counter if (do_enq || do_deq);
    if (do_enq)
      begin
        if (pipelined)
          begin
            if (do_deq) // simultaneous enq & deq
              filled <= shiftInAt0(replicate(False), True);
            else // enq only
              filled <= shiftInAt0(filled, True);
          end
        else
          filled <= shiftInAt0(filled, True);
      end
    else // deq only
      filled <= replicate(False);
  endrule

  method Action enq(el_type el) if (can_enq);
    vec <= shiftInAtN(vec, el);
    do_enq.send();
  endmethod
        
  method Action deq if (full);
    do_deq.send();
  endmethod

  method Vector#(size, el_type) data = vec;

  method Vector#(size, Bool) guage = filled;

  method Bool isFull = full;

endmodule : mkSIPO



interface MyShiftReg #(numeric type size, type el_type);
  (* always_ready *)
  method Action enq(el_type in_data); 
  (* always_ready *)
  method Vector#(size, el_type) data;
endinterface

module mkMyShiftReg (MyShiftReg#(size, el_type)) provisos (Bits#(el_type, width));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;

  method Action enq(el_type v);
    vec <= shiftInAtN(vec, v);
  endmethod
  method Vector#(size, el_type) data;
    return vec;
  endmethod
endmodule : mkMyShiftReg

endpackage : SIPO