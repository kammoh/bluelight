package AsconLwc;

import LwcApi :: *;
import Ascon :: *;

Integer key_bytes = 16;
Integer abytes = 16;
Integer hash_bytes = 32;

(* default_clock_osc = "clk", default_reset = "rst" *)
module lwc (LwcIfc#(32));
    let ascon <- mkAscon;
    let lwc <- mkLwc(ascon, True, key_bytes, abytes, hash_bytes);
    return lwc;
endmodule

endpackage : AsconLwc