/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Original resolution-independent shell pictograms. Real GDI spans, no icon
 * font, borrowed artwork, alpha blending, network state or bitmap assets. */
#ifndef SHZ_SHELL_ICONS_H
#define SHZ_SHELL_ICONS_H

enum { SHZ_ICON_COMPUTER, SHZ_ICON_FOLDER, SHZ_ICON_RUN, SHZ_ICON_THEME,
       SHZ_ICON_DROP, SHZ_ICON_DRIVE, SHZ_ICON_DOCUMENT, SHZ_ICON_UP, SHZ_ICON_REFRESH };
static COLORREF ShzTint(COLORREF a, COLORREF b, int percent)
{
    int p = ShzClamp(percent, 0, 100);
    return RGB((GetRValue(a) * (100-p) + GetRValue(b) * p) / 100,
               (GetGValue(a) * (100-p) + GetGValue(b) * p) / 100,
               (GetBValue(a) * (100-p) + GetBValue(b) * p) / 100);
}
static void ShzIconPart(HDC dc, const RECT *b, int x, int y, int w, int h, COLORREF c)
{
    RECT r;
    r.left = b->left + (b->right-b->left)*x/64; r.top = b->top + (b->bottom-b->top)*y/64;
    r.right = b->left + (b->right-b->left)*(x+w)/64; r.bottom = b->top + (b->bottom-b->top)*(y+h)/64;
    ShzFill(dc, &r, c);
}
static void ShzIconFrame(HDC dc, const RECT *b, int x, int y, int w, int h, COLORREF edge, COLORREF fill, COLORREF hi)
{
    ShzIconPart(dc,b,x,y,w,h,edge); ShzIconPart(dc,b,x+3,y+3,w-6,h-6,fill);
    ShzIconPart(dc,b,x+3,y+3,w-6,3,hi);
}
static void ShzDrawIcon(HDC dc, const RECT *b, int kind, COLORREF accent)
{
    COLORREF dark = ShzTint(accent, RGB(12,28,44), 40), light = ShzTint(accent, RGB(255,255,255), 62);
    COLORREF sheen = ShzTint(accent, RGB(255,255,255), 30), deep = ShzTint(accent, RGB(12,28,44), 62);
    COLORREF paper = RGB(250,251,252), shade = ShzTint(accent, RGB(150,160,172), 55);
    int i;
    if (b->right <= b->left || b->bottom <= b->top || (long long)b->right-b->left > 256 || (long long)b->bottom-b->top > 256) return;
    switch (kind) {
    case SHZ_ICON_COMPUTER:
        ShzIconPart(dc,b,6,53,52,3,deep);                      /* ground shadow */
        ShzIconFrame(dc,b,4,6,56,38,dark,deep,accent);          /* bezel */
        ShzIconPart(dc,b,10,12,44,26,accent);                   /* screen */
        ShzIconPart(dc,b,10,12,44,8,sheen);                     /* upper sheen */
        for(i=0;i<10;i++) ShzIconPart(dc,b,10+i*2,30-i*2,2,2+i*2,ShzTint(accent,light,25+i*3)); /* diagonal glare */
        ShzIconPart(dc,b,26,44,12,5,dark); ShzIconPart(dc,b,27,44,10,2,shade);  /* neck */
        ShzIconPart(dc,b,16,49,32,5,dark); ShzIconPart(dc,b,17,50,30,2,light); /* base */
        ShzIconPart(dc,b,47,40,3,2,light); break;               /* power LED */
    case SHZ_ICON_FOLDER:
        ShzIconPart(dc,b,4,12,24,10,dark); ShzIconPart(dc,b,6,13,20,7,light);   /* tab */
        ShzIconPart(dc,b,28,16,5,6,dark);
        ShzIconPart(dc,b,4,18,56,38,dark);                                      /* back */
        ShzIconPart(dc,b,6,20,52,8,light);                                      /* open back */
        ShzIconPart(dc,b,4,28,56,28,dark); ShzIconPart(dc,b,6,30,52,24,accent);  /* front */
        ShzIconPart(dc,b,6,30,52,5,sheen); ShzIconPart(dc,b,6,30,52,2,light);
        ShzIconPart(dc,b,6,50,52,4,ShzTint(accent,dark,35)); break;
    case SHZ_ICON_RUN:
        ShzIconPart(dc,b,4,8,56,48,dark); ShzIconPart(dc,b,6,10,52,44,light);   /* window */
        ShzIconPart(dc,b,6,10,52,9,accent); ShzIconPart(dc,b,6,10,52,3,sheen);   /* title bar */
        ShzIconPart(dc,b,48,12,6,5,light); ShzIconPart(dc,b,49,13,4,3,dark);     /* close box */
        ShzIconPart(dc,b,9,22,46,29,RGB(20,34,46));                              /* console */
        for(i=0;i<7;i++) ShzIconPart(dc,b,15+i,27+i,3,3,paper);                 /* chevron */
        for(i=0;i<7;i++) ShzIconPart(dc,b,21-i,34+i,3,3,paper);
        ShzIconPart(dc,b,28,41,14,3,paper); break;                               /* cursor */
    case SHZ_ICON_DROP:
        for(i=0;i<28;i++) ShzIconPart(dc,b,31-i,5+i,2+i*2,1,ShzTint(accent,light,20+i));
        for(i=0;i<22;i++) { int inset=(i*i)/26; ShzIconPart(dc,b,4+inset,33+i,56-inset*2,1,ShzTint(accent,dark,i*30/22)); }
        ShzIconPart(dc,b,17,30,5,15,light); ShzIconPart(dc,b,18,32,2,6,paper);   /* highlight */
        break;
    case SHZ_ICON_THEME:
        ShzIconPart(dc,b,4,5,56,56,dark);
        ShzIconPart(dc,b,7,8,24,24,accent); ShzIconPart(dc,b,33,8,24,24,light);
        ShzIconPart(dc,b,7,34,24,24,dark); ShzIconPart(dc,b,33,34,24,24,ShzTint(accent,RGB(72,180,145),65));
        ShzIconPart(dc,b,7,8,24,3,sheen); ShzIconPart(dc,b,33,8,24,3,paper);
        ShzIconPart(dc,b,7,34,24,3,accent); ShzIconPart(dc,b,33,34,24,3,light); break;
    case SHZ_ICON_DRIVE:
        ShzIconPart(dc,b,6,19,52,32,dark); ShzIconPart(dc,b,8,21,48,28,light);   /* chassis */
        ShzIconPart(dc,b,8,21,48,4,paper);
        ShzIconPart(dc,b,10,28,44,10,shade); ShzIconPart(dc,b,10,28,44,2,dark);   /* bay */
        ShzIconPart(dc,b,10,41,44,6,accent); ShzIconPart(dc,b,10,41,44,2,sheen);  /* label */
        ShzIconPart(dc,b,44,43,6,2,paper);                                        /* LED */
        ShzIconPart(dc,b,10,51,6,3,dark); ShzIconPart(dc,b,48,51,6,3,dark); break; /* feet */
    case SHZ_ICON_DOCUMENT:
        ShzIconPart(dc,b,13,4,36,56,dark); ShzIconPart(dc,b,15,6,32,52,paper);
        for(i=0;i<12;i++) ShzIconPart(dc,b,37+i,4+i/1,12-i,1,dark);               /* clipped corner */
        ShzIconPart(dc,b,37,6,10,10,light); ShzIconPart(dc,b,37,16,10,1,dark); ShzIconPart(dc,b,37,6,1,10,dark);
        ShzIconPart(dc,b,20,22,22,2,accent);
        for(i=0;i<4;i++) ShzIconPart(dc,b,20,28+i*7,i==3?14:24,2,shade);
        break;
    case SHZ_ICON_UP:
        for(i=0;i<17;i++) ShzIconPart(dc,b,31-i,10+i,2+i*2,2,i<3?light:accent);   /* head */
        ShzIconPart(dc,b,25,28,14,26,dark); ShzIconPart(dc,b,27,28,10,24,accent);  /* shaft */
        ShzIconPart(dc,b,27,28,3,24,sheen); break;
    default:
        ShzIconPart(dc,b,10,13,38,6,accent); ShzIconPart(dc,b,10,13,6,29,accent);
        ShzIconPart(dc,b,16,43,38,6,accent); ShzIconPart(dc,b,48,25,6,24,accent);
        ShzIconPart(dc,b,10,13,38,2,sheen); ShzIconPart(dc,b,16,47,38,2,dark);
        ShzIconPart(dc,b,39,8,15,15,accent); ShzIconPart(dc,b,39,8,15,3,light); break;
    }
}
#endif
