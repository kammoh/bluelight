package BusDefines;

import FIFO :: *;

interface BusSender#(type a);
    method Action put(a value);
    interface BusSend#(a) out;
endinterface

interface BusReceiver#(type a);
    interface BusRecv#(a) in;
    method ActionValue#(a) get;
endinterface

(* always_ready, always_enabled *)
interface BusSend#(type a);
    method a  data;
    method Bool valid;
    (* prefix="" *)
    method Action ready((* port="ready" *) Bool value);
endinterface

(* always_ready, always_enabled *)
interface BusRecv#(type a);
    (* prefix="" *)
    method Action data((* port="data" *) a value);
    (* prefix="" *)
    method Action valid((* port="valid" *) Bool value);
    method Bool ready;
endinterface

endpackage
