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
   default_reset = "rst", synthesize *)
module `TOP_MODULE_NAME (LwcIfc#(32));
  Integer key_bytes = 16;
  Integer abytes = 16;
  Integer hash_bytes = 32;
  let xoodyak <- mkXoodyak;
  let lwc <- mkLwc(xoodyak, True, key_bytes, abytes, hash_bytes);
  return lwc;
endmodule

endpackage : XoodyakLwc