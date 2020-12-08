package XoodyakLwc;

import LwcApi :: *;
import Xoodyak :: *;

`ifndef TOP_MODULE_NAME
`define TOP_MODULE_NAME lwc
`endif

(* default_clock_osc = "clk",
   default_reset = "rst" *)
module `TOP_MODULE_NAME (LwcIfc);
  let xoodyak <- mkXoodyak;
  let lwc <- mkLwc(xoodyak);
  return lwc;
endmodule

endpackage : XoodyakLwc