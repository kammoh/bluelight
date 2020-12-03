package BusAdaptor;

interface FifoOut#(type a);
  method Action deq;
  (* always_ready *)
  method Bool notEmpty;
  (* always_ready *)
  method a first;
endinterface

interface BusReceiver#(type a);
  interface BusRecv#(a) in;
  (* always_ready *)
  method ActionValue#(Maybe#(a)) tryGet;
endinterface

(* always_ready, always_enabled *)
interface BusRecv#(type a);
  (* prefix="" *)
  method Action data((* port="data" *) a value);
  (* prefix="" *)
  method Action valid((* port="valid" *) Bool value);
  method Bool ready;
endinterface

(* always_ready, always_enabled *)
interface BusSend#(type a);
  method a  data;
  method Bool valid;
  (* prefix="" *)
  method Action ready((* port="ready" *) Bool value);
endinterface

////////////////////////////////////////////////////////////////////////////////

module mkBusReceiver (BusReceiver#(a)) provisos(Bits#(a, sa));
  Wire#(a) data_wire <- mkBypassWire;
  PulseWire is_ready <- mkPulseWire;
  PulseWire is_valid <- mkPulseWire;

  // from the bus
  interface BusRecv in;
    method Action data(a value);
      data_wire <= value;
    endmethod
    method Action valid(Bool value);
      if (value) is_valid.send;
    endmethod
    method Bool ready;
      return is_ready;
    endmethod
  endinterface

  // to the receiver\
  method ActionValue#(Maybe#(a)) tryGet;
    is_ready.send();
    return is_valid ? tagged Valid data_wire : tagged Invalid;
  endmethod
endmodule

module mkBusSender#(FifoOut#(a) outfifo) (BusSend#(a)) provisos(Bits#(a, sa));
  PulseWire deq_ready <- mkPulseWire;

  rule do_deq (outfifo.notEmpty && deq_ready);
    outfifo.deq;
  endrule

  method a data;
    return outfifo.first;
  endmethod
  method Bool valid;
    return outfifo.notEmpty;
  endmethod
  method Action ready(Bool value);
    if (value) deq_ready.send;
  endmethod
endmodule

endpackage : BusAdaptor
