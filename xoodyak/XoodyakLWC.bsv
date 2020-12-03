package XoodyakLWC;

import LWC :: *;
import Xoodyak :: *;

(* default_clock_osc = "clk",
   default_reset = "rst_n" *)
module mkXoodyakLWC (LWCIfc);
  let xoodyak <- mkXoodyak;
  let lwc <- mkLWC(xoodyak);
  return lwc;
endmodule

endpackage : XoodyakLWC