package PISO;

import Vector::*;

typedef UInt#(TLog#(TAdd#(size,1))) CountType#(numeric type size);

interface PISO #(numeric type size, type el_type);
  method Action enq(Vector#(size,el_type) data, CountType#(size) n); // n in 1...size
  method Action deq;
  (* always_ready *)
  method Bool notEmpty;
  (* always_ready *)
  method el_type first;
endinterface

// Bypass PISO
// if empty enq can happen simultanously with deq of first element 
// module mkBypassPISO (PISO#(size, el_type)) provisos (Bits#(el_type, el_type_sz__), Add#(1,a__,size));
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
module mkPISO (PISO#(size, el_type)) provisos (Bits#(el_type, el_type_sz__), Add#(1,a__,size));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;
  Reg#(CountType#(size)) countReg <- mkReg(0);

  Bool not_empty = (countReg != 0);

  method Action enq(Vector#(size,el_type) data, CountType#(size) n) if (!not_empty);
    // rwEnq.wset(tuple2(data, n));
    vec <= data;
    countReg <= n;
  endmethod
        
  // method Action deq if (!empty || isValid(rwEnq.wget()));
  method Action deq if (not_empty);
    // pwDeq.send();
    vec <= shiftInAtN(vec, vec[valueOf(size)-1]);
    countReg <= countReg - 1;
  endmethod

  method el_type first;
    // if (empty &&& rwEnq.wget matches tagged Valid {.v,.*} )
    //   return v[0];
    // else
    return head(vec);
  endmethod

  method Bool notEmpty;
    return not_empty;
  endmethod

endmodule : mkPISO

endpackage : PISO