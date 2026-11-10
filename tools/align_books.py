import sys
from PIL import Image, ImageDraw, ImageFilter
src=Image.open(sys.argv[1]).convert('RGB')
# (top_left_x, top_right_x, top_y, bottom_left_x, bottom_right_x, bottom_y)
B=[(70,187,143,74,190,988),(195,302,142,195,297,990),(307,440,142,300,430,990),
(446,584,148,430,569,995),(586,676,152,569,656,995),(678,805,158,656,784,1010),
(810,907,85,784,876,1015),(915,1056,80,876,1010,1020),(1061,1163,85,1013,1128,1020),
(1163,1266,160,1128,1225,1015),(1271,1404,92,1225,1358,1015),(1409,1532,178,1358,1491,1025),
(1532,1650,190,1491,1604,1040),(1660,1783,110,1604,1712,1060),(1792,1973,110,1717,1896,1065),
(1985,2145,118,1901,2068,1055),(2145,2260,200,2068,2178,1078),(2260,2385,208,2178,2299,1085),
(2385,2481,213,2299,2395,1092),(2481,2613,215,2395,2557,1100),(2640,2762,137,2557,2694,1100),
(2765,2836,140,2694,2760,1105),(2836,2937,225,2760,2866,1110),(2937,3063,230,2866,3002,1120),
(3063,3215,238,3002,3144,1135),(3215,3367,245,3144,3301,1145),(3367,3508,250,3301,3427,1160),
(3508,3635,255,3427,3554,1168),(3635,3812,258,3554,3691,1180),(3812,3949,262,3691,3822,1190)]
H=880; pad=60; top=60
spines=[]
for tl,tr,ty,bl,br,by in B:
    w=round(((tr-tl)+(br-bl))/2)
    q=(tl,ty+3, bl,by-3, br,by-3, tr,ty+3)
    spines.append(src.transform((w,H),Image.QUAD,q,Image.BICUBIC))
W=sum(s.width for s in spines)+2*pad
canvas=Image.new('RGB',(W,H+top+90),(236,233,228))
sh=Image.new('L',canvas.size,0); ImageDraw.Draw(sh).rectangle([pad-4,top+8,W-pad+8,top+H+14],fill=110)
sh=sh.filter(ImageFilter.GaussianBlur(14))
canvas.paste((60,50,40),mask=sh)
ImageDraw.Draw(canvas).rectangle([pad-30,top+H,W-pad+30,top+H+22],fill=(150,120,85))
x=pad
for s in spines: canvas.paste(s,(x,top)); x+=s.width
canvas.save(sys.argv[2],quality=95)
print(canvas.size)
