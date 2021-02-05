package GimliRound;

import Vector :: *;
import BluelightUtils :: *;

export Vector :: *;
export GimliRound :: *;

typedef TDiv#(128, 8) GimliBlockBytes;
typedef 4 WordBytes;
typedef Vector#(WordBytes, Byte) Word;
typedef Vector#(TDiv#(GimliBlockBytes, WordBytes), Word) GimliBlock;
typedef Vector#(3, GimliBlock) GimliState;


typedef 24 CipherRounds;
typedef Bit#(TLog#(CipherRounds)) Round;

function GimliState spBox(GimliState s);
    GimliState sp = newVector;
    for (Integer j = 0; j <= 3; j = j + 1) begin
        let x = rotateLeft(s[0][j], 24'b0);
        let y = rotateLeft(s[1][j], 9'b0);
        let z = pack(s[2][j]);
        sp[2][j] = unpack( x ^ (z << 1) ^ ((y & z) << 2) );
        sp[1][j] = unpack( y ^    x     ^ ((x | z) << 1) );
        sp[0][j] = unpack( z ^    y     ^ ((x & y) << 3) );
    end
    return sp;
endfunction

function GimliState singleRound(GimliState s, Round r);
    GimliState sp = spBox(s);
    let rMod4Is0 = r[1:0] == 0;
    let rMod4Is2 = r[1:0] == 2;
    let small_swap = cons(sp[0][1], cons(sp[0][0], cons(sp[0][3], cons(sp[0][2], nil))));
    if (rMod4Is0)
        sp[0] = small_swap;
    else if (rMod4Is2)
        sp[0] = reverse(small_swap);
    if (rMod4Is0)
        sp[0][0] = unpack( pack(sp[0][0]) ^ {24'h9e3779, zeroExtend(r)} );
    return sp;
endfunction

endpackage