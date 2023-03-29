package PISO;

import Vector::*;

import CryptoCore::*;

export Vector::*;
export PISO :: *;

typedef UInt#(TLog#(TAdd#(size,1))) CountType#(numeric type size);

// similar to out-side of FIFOCountIfc + FIFO.enq
interface PISO #(numeric type size, type el_type);
  method Action enq(WithLast#(Vector#(size,el_type)) data_with_last, Vector#(size, Bool) guage);
  method Action deq;
  (* always_ready *)
  method WithLast#(el_type) first;
  (* always_ready *)
  method Bool notEmpty;
endinterface

// Bypass PISO
// if empty enq can happen simultanously with deq of first element 
// module mkBypassPiso (PISO#(size, el_type)) provisos (Bits#(el_type, el_type_sz__), Add#(1,a__,size));
  // RWire#(Tuple2#(Vector#(size, el_type), CountType#(size))) rwEnq <- mkRWire();
  // let pwDeq <- mkPulseWire();
  // rule update if (isValid(rwEnq.wget) || pwDeq);
  //   case (rwEnq.wget) matches
  //     tagged Valid {.v, .n}:
  //     begin
  //       // if (pwDeq) // simultanous enq & deq when empty
  //       // begin
  //       //   vec <= shiftInAtN(v, vec[valueOf(size)-1]);
  //       //   countReg <= n - 1;
  //       // end
  //       // else  // enq only
  //       // begin
  //         vec <= v;
  //         countReg <= n;
  //       // end
  //     end
  //     tagged Invalid: // deq only
  //       if (pwDeq)
  //       begin
  //         vec <= shiftInAtN(vec, vec[valueOf(size)-1]);
  //         countReg <= countReg - 1;
  //       end
  //     endcase
  // endrule


// **** NO BYPASS
// (* always_ready = "out.notEmpty,out.first" *)
module mkPISO (PISO#(size, el_type)) provisos (Bits#(el_type, el_type_sz__), Add#(1,a__,size), Add#(2,b__,size));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;
  Reg#(Vector#(size, Bool)) filled <- mkReg(replicate(False)); // only lsb needs to be 0
  Reg#(Bool) last_block <- mkRegU;

  Bool not_empty = head(filled);
  Bool empty = !not_empty;

  method Action enq(WithLast#(Vector#(size,el_type)) data_with_last, Vector#(size, Bool) guage) if(empty);
    vec <= data_with_last.data;
    last_block <= data_with_last.last;
    filled <= guage;
  endmethod

  method Action deq if (not_empty);
    // vec <= shiftInAtN(vec, ?);
    vec <= shiftInAtN(vec, last(vec));
    filled <= shiftInAtN(filled, False);
  endmethod

  method WithLast#(el_type) first = WithLast {data: head(vec), last: last_block && !filled[1]};

  method Bool notEmpty = not_empty;

endmodule : mkPISO

endpackage : PISO