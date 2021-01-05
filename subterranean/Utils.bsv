package Utils;

// import Vector :: *;

// Integer multiplicativeSubgroupArray[32] = {1, 176, 136, 35, 249, 134, 197, 234, 64, 213, 223, 184, 2, 95, 15, 70, 241, 11, 137, 211, 128, 169, 189, 111, 4, 190, 30, 140, 225, 22, 17, 165};
// Vector#(32, Integer) multiplicativeSubgroup = arrayToVector(multiplicativeSubgroupArray);

function Bit#(257) pi (Bit#(257) s);
  Bit#(257) r;
  Integer i;
  for(i=0; i<257; i=i+1)
    r[i] = s[(12*i) % 257];
  return r;
endfunction

endpackage : Utils