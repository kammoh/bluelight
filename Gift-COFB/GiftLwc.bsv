package GiftLwc;

import LwcApi :: *;
import Gift :: *;

(* default_clock_osc = "clk", default_reset = "rst" *)
module lwc (LwcIfc);
    let gift <- mkGift;
    let lwc <- mkLwc(gift, True, True);
    return lwc;
endmodule

endpackage : GiftLwc