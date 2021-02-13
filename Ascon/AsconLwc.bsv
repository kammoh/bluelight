package AsconLwc;

import LwcApi :: *;
import Ascon :: *;

(* default_clock_osc = "clk", default_reset = "rst" *)
module lwc (LwcIfc);
    let ascon <- mkAscon;
    let lwc <- mkLwc(ascon, True, True);
    return lwc;
endmodule

endpackage : AsconLwc