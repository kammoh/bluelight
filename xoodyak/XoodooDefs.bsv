package XoodooDefs;

import Vector :: *;
import CryptoCore :: *;

typedef 32 LaneWidth;
typedef Bit#(LaneWidth) XoodooLane;

typedef 4 NumLanesInPlane;
typedef 3 NumPlanes;
typedef TMul #(NumLanesInPlane, NumPlanes) NumLanesInState;
Integer numLanesInState = valueOf(NumLanesInState);

// 1: unrolled, 2: unrolled 2x  //// FIXME optimize for 2
typedef 1 UnrollFactor;

typedef 12 XoodyakRounds;

typedef TDiv#(XoodyakRounds, UnrollFactor) NumRounds;

typedef 44 Xoodyak_Rkin;
typedef 24 Xoodyak_Rkout;
typedef 16 Xoodyak_Rhash;

typedef TDiv#(Xoodyak_Rkin,  4) MaxInRateLanes; // 44 bytes
typedef TDiv#(Xoodyak_Rkout, 4) MaxOutRateLanes;// 24 bytes

typedef Vector #(NumLanesInPlane, XoodooLane) XoodooPlane;
typedef Vector #(NumPlanes, XoodooPlane) XoodooState;

Bit#(10) roundConst[valueOf(XoodyakRounds)] = {'h058, 'h038, 'h3C0, 'h0D0, 'h120, 'h014, 'h060, 'h02C, 'h380, 'h0F0, 'h1A0, 'h012};

function Action dump_state(String msg, XoodooState state);
  action
    $write("%s  ", msg);
    for(Integer i = 0; i < valueOf(NumLanesInState); i = i + 1) begin
      $write("%08x ", state[i/valueOf(NumLanesInPlane)][i%valueOf(NumLanesInPlane)]);
      if(i == 3 || i == 7)
        $write("- ");
    end
    $display("");
  endaction
endfunction

function XoodooPlane shiftLeft(XoodooPlane plane, UInt#(2) t, UInt#(5) v);
  for(Integer i=0; i < valueof(NumLanesInPlane); i = i + 1)
    plane[i] = rotateBitsBy(plane[i], v);
  return rotateBy(plane, t);
endfunction

function XoodooState theta(XoodooState state);
  XoodooPlane p = unpack(pack(state[0]) ^ pack(state[1]) ^ pack(state[2]));
  let e = pack(shiftLeft(p, 1, 5)) ^ pack(shiftLeft(p, 1, 14));
  for(Integer y = 0 ; y < valueOf(NumPlanes) ; y = y + 1)
    state[y] = unpack(pack(state[y]) ^ e);
  return state;
endfunction

function XoodooState rho_west(XoodooState state);
  state[1] = shiftLeft(state[1], 1, 0);
  state[2] = shiftLeft(state[2], 0, 11);
  return state;
endfunction

function XoodooState iota(XoodooState a, UInt#(TLog#(XoodyakRounds)) r);
  a[0][0][9:0] = unpack(pack(a[0][0])[9:0] ^ roundConst[r]);
  return a;
endfunction

function XoodooState chi(XoodooState a);
  for(Integer y = 0 ; y < valueOf(NumPlanes) ; y = y + 1)
    a[y] = unpack(pack(a[y]) ^ (~pack(a[ (y+1)%3 ]) & pack(a[ (y+2)%3 ])));
  return a;
endfunction

function XoodooState rho_east(XoodooState state);
  state[1] = shiftLeft(state[1], 0, 1);
  state[2] = shiftLeft(state[2], 2, 8);
  return state;
endfunction

// Full single Xoodoo round
function XoodooState singleRound(XoodooState state, UInt#(TLog#(XoodyakRounds)) r);
  return rho_east(chi(iota(rho_west(theta(state)), r)));
endfunction

// Full Xoodoo round, possibly unrolled UnrollFactor times
function XoodooState round(XoodooState prev_state, UInt#(TLog#(NumRounds)) r) provisos(Mul#(UnrollFactor, _n, XoodyakRounds) );
  XoodooState next_state;
  next_state = prev_state;
  UInt#(TLog#(XoodyakRounds)) r_step = fromInteger(valueOf(UnrollFactor)) * zeroExtend(r);
  Integer i;
  for (i=0; i < valueOf(UnrollFactor); i = i + 1)
    next_state = singleRound(next_state, r_step + fromInteger(i));
  return next_state;
endfunction

endpackage : XoodooDefs