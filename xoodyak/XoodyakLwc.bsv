package XoodyakLwc;

import LwcApi :: *;
`ifdef UNROLLED
import Xoodyak2x :: *;
`else
import Xoodyak :: *;
`endif

`ifndef TOP_MODULE_NAME
`define TOP_MODULE_NAME lwc
`endif

(* default_clock_osc = "clk",
   default_reset = "rst" *)
module `TOP_MODULE_NAME (LwcIfc);
  let xoodyak <- mkXoodyak;
  let lwc <- mkLwc(xoodyak, True, False);
  return lwc;
endmodule

endpackage : XoodyakLwc