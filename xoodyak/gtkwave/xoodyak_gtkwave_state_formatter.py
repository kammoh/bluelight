#!/usr/bin/env python3

import sys
import tempfile

def chunks(x, n):
    return [x[i:i+n] for i in range(0, len(x), n)]


COLORS = [
    #	"alice blue",
    #	"aquamarine",
    #	"azure",
    #	"beige",
    #	"bisque",
   	# "black",
    #	"blanched almond",
   	"blue",
   	"blue violet",
   	"brown",
   	"burlywood",
   	"cadet blue",
    #	"chartreuse",
   	"chocolate",
    #	"coral",
   	"cornflower blue",
    #	"cornsilk",
    #	"cyan",
   	"dark blue",
   	"dark cyan",
    #	"dark goldenrod",
   	"dark green",
   	"dark khaki",
   	"dark magenta",
   	"dark olive green",
   	"dark orange",
   	"dark orchid",
   	"dark red",
   	"dark salmon",
   	"dark sea green",
   	"dark slate blue",
   	"dark turquoise",
   	"dark violet",
   	"deep pink",
   	"deep sky blue",
   	"dodger blue",
   	"firebrick",
   	"forest green",
    #	"gainsboro",
   	"gold",
    #	"goldenrod",
    #	"green",
    #	"green yellow",
    #	"honeydew",
   	"hot pink",
   	"indian red",
    #	"ivory",
   	"khaki",
    #	"lavender",
    #	"lavender blush",
    #	"lawn green",
    #	"lemon chiffon",
    #	"light blue",
    #	"light coral",
    #	"light cyan",
    #	"light goldenrod",
    #	"light goldenrod yellow",
    #	"light green",
    #	"light pink",
    #	"light salmon",
    #	"light sea green",
    #	"light sky blue",
    #	"light slate blue",
    #	"light steel blue",
    #	"light yellow",
    #	"lime green",
    #	"linen",
   	"magenta",
   	"maroon",
   	"medium aquamarine",
   	"medium blue",
   	"medium orchid",
   	"medium purple",
   	"medium sea green",
   	"medium slate blue",
   	"medium spring green",
   	"medium turquoise",
   	"medium violet red",
   	"midnight blue",
    #	"mint cream",
    #	"misty rose",
    #	"moccasin",
   	"navy",
   	"navy blue",
    #	"old lace",
   	"olive drab",
   	"orange",
   	"orange red",
   	"orchid",
    #	"pale goldenrod",
    #	"pale green",
    #	"pale turquoise",
   	"pale violet red",
    #	"papaya whip",
    #	"peach puff",
   	"peru",
   	"pink",
   	"plum",
    #	"powder blue",
   	"purple",
   	"red",
   	"rosy brown",
   	"royal blue",
   	"saddle brown",
   	"salmon",
   	"sandy brown",
    #	"sea green",
    #	"seashell",
   	"sienna",
   	"sky blue",
   	"slate blue",
    #	"snow",
    #	"spring green",
   	"steel blue",
   	"tan",
   	"thistle",
   	"tomato",
   	"turquoise",
   	"violet",
   	"violet red",
    #	"wheat",
    #	"yellow",
   	"yellow green",
]

values = [
    "e22301a1 00a05c42 652c9558 734259dd - 8a0853d1 ed88f2bc 06732668 3573d37c - 0fd74484 d47dfc2e f32c50c6 4c6fb51e",
    "18a64ed6 d3d6b8e5 c8a78fb7 6fffbf1a - 5873e013 3391718a d09b4530 a42b3cf4 - 76e816eb a286d141 2bff1573 660e066d",
    "18a73680 d3d6b8e5 c8a78fb7 6fffbf1a - 5873e013 3391718a d09b4530 a42b3cf4 - 76e816eb a286d141 2bff1573 e50e066d",
    "19b73680 d3d6b8e5 c8a78fb7 6fffbf1a - 5873e013 3391718a d09b4530 a42b3cf4 - 76e816eb a286d141 2bff1573 e50e066d",
    "15ea7d55 68c4827a 27685366 9ef2b626 - 3f6bb12b 17a6663a 846102dd d56cc241 - 9fc2033c c73b5c7a d99fc803 9aa2a73d",
    "14fb4947 68c4827a 27685366 9ef2b626 - 3f6bb12b 17a6663a 846102dd d56cc241 - 9fc2033c c73b5c7a d99fc803 daa2a73d",
    "1d5071dd 26e158a0 d05e5388 5dab2203 - 4e3da82a ccbadf9b 485287e0 72c2eba9 - ba76117e 04fab562 a686824e f9433538",
]

def main(argv):
    while True:
        line = sys.stdin.readline()
        if not line:
            return 0

        b = list(reversed(chunks(line.strip(),2)))
        planes = chunks(["".join(list(reversed(x))) for x in chunks(b, 4)], 4)
        line = " - ".join(" ".join(p) for p in planes).lower()

        try:
            line = f"?{COLORS[values.index(line)]}?" + line
        except:
            pass

        sys.stdout.write(f'{line}\n')
        sys.stdout.flush()
    return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv))
