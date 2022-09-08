package GimliLwc;

import LwcApi :: *;
import Gimli :: *;

(* default_clock_osc = "clk", default_reset = "rst" *)
module lwc (LwcIfc);
    let gimli <- mkGimli;
    let lwc <- mkLwc(gimli, True, True);
    return lwc;
endmodule

endpackage : GimliLwc