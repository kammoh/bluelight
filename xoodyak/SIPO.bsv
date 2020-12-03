package SIPO;

import Vector::*;


interface SIPO #(numeric type size, type el_type);
  method Action enq(el_type in_data); 
  method Action deq;
  method UInt#(TLog#(TAdd#(size,1))) count;
  method UInt#(TLog#(TAdd#(size,1))) countPlusOne;
  method Bool isFull;
  method Vector#(size, el_type) data;
endinterface

// Pipelined SIPO (Serial In, Parallel Out)
// if full enq can happen simultanously with deq of first element 
module mkPipelineSIPO (SIPO#(size, el_type)) provisos (Bits#(el_type, el_type_sz));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;
  Reg#(UInt#(TLog#(TAdd#(size,1)))) count_reg <- mkReg(0);
  UInt#(TLog#(TAdd#(size,1))) count_plus_one = count_reg + 1;
  RWire#(el_type) rwEnq <- mkRWire();
  let pwDeq <- mkPulseWire();



  Bool full = (count_reg == fromInteger(valueOf(size)));
  
  (* fire_when_enabled, no_implicit_conditions *)
  rule update if (isValid(rwEnq.wget) || pwDeq);
    case (rwEnq.wget) matches
      tagged Valid .v:
        begin
          vec <= shiftInAtN(vec, v);
          if (pwDeq) // simultanous enq & deq
            count_reg <= 1;
          else // enq only
            count_reg <= count_plus_one;
        end
      tagged Invalid: // deq only
        count_reg <= 0;
    endcase
  endrule

  method Action enq(el_type el) if (!full || pwDeq);
    rwEnq.wset(el);
  endmethod
        
  method Action deq if (full);
    pwDeq.send();
  endmethod

  method Vector#(size, el_type) data;
    return vec;
  endmethod

  method UInt#(TLog#(TAdd#(size,1))) count;
    return count_reg;
  endmethod

  method UInt#(TLog#(TAdd#(size,1))) countPlusOne;
    return count_plus_one;
  endmethod

  method Bool isFull;
    return full;
  endmethod
endmodule : mkPipelineSIPO


module mkSIPO (SIPO#(size, el_type)) provisos (Bits#(el_type, el_type_sz));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;
  Reg#(UInt#(TLog#(TAdd#(size,1)))) count_reg <- mkReg(0);
  UInt#(TLog#(TAdd#(size,1))) count_plus_one = count_reg + 1;

  Bool full = (count_reg == fromInteger(valueOf(size)));

  method Action enq(el_type v) if (!full);
    vec <= shiftInAtN(vec, v);
    count_reg <= count_plus_one;
  endmethod
        
  method Action deq if (full);
    count_reg <= 0;
  endmethod

  method Vector#(size, el_type) data;
    return vec;
  endmethod

  method UInt#(TLog#(TAdd#(size,1))) count;
    return count_reg;
  endmethod

  method UInt#(TLog#(TAdd#(size,1))) countPlusOne;
    return count_plus_one;
  endmethod

  method Bool isFull;
    return full;
  endmethod

endmodule : mkSIPO

endpackage : SIPO