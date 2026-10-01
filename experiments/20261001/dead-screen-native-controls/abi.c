/* SPDX-License-Identifier: GPL-2.0-only
 * Host compiler ABI receipt for the HELD native candidate, not a guest record.
 */
#include "dead_screen.h"
#include <stdio.h>
#define FIELD(T,F) printf("\"" #F "\":%zu,",offsetof(T,F))
int main(void)
{
    printf("{\"state_size\":%zu,\"fault_size\":%zu,\"surface_size\":%zu,",sizeof(ds_state),sizeof(ds_fault),sizeof(ds_surface));
    printf("\"state\":{");
    FIELD(ds_state,fault);FIELD(ds_state,tetris);FIELD(ds_state,suika);FIELD(ds_state,rng);FIELD(ds_state,ticks);
    FIELD(ds_state,latched);FIELD(ds_state,korean);FIELD(ds_state,mode);FIELD(ds_state,show_trace);FIELD(ds_state,graphics_failed);
    printf("\"end\":%zu},\"fault\":{",sizeof(ds_state));
    FIELD(ds_fault,ip);FIELD(ds_fault,sp);FIELD(ds_fault,bp);FIELD(ds_fault,flags);FIELD(ds_fault,vector);
    FIELD(ds_fault,error);FIELD(ds_fault,cr2);FIELD(ds_fault,cr3);FIELD(ds_fault,reg);FIELD(ds_fault,frames);
    FIELD(ds_fault,frame_count);FIELD(ds_fault,registers_valid);FIELD(ds_fault,reason);
    printf("\"end\":%zu},\"tetris\":{",sizeof(ds_fault));
    FIELD(ds_tetris,board);FIELD(ds_tetris,x);FIELD(ds_tetris,y);FIELD(ds_tetris,piece);FIELD(ds_tetris,rotation);
    FIELD(ds_tetris,fall);FIELD(ds_tetris,lines);FIELD(ds_tetris,score);FIELD(ds_tetris,over);
    printf("\"end\":%zu},\"suika\":{",sizeof(ds_tetris));
    FIELD(ds_suika,ball);FIELD(ds_suika,aim);FIELD(ds_suika,next);FIELD(ds_suika,cooldown);
    FIELD(ds_suika,score);FIELD(ds_suika,over);
    printf("\"end\":%zu},\"ball\":{",sizeof(ds_suika));
    FIELD(ds_ball,x);FIELD(ds_ball,y);FIELD(ds_ball,vx);FIELD(ds_ball,vy);FIELD(ds_ball,used);
    FIELD(ds_ball,level);FIELD(ds_ball,ceiling_ticks);
    printf("\"end\":%zu},\"surface\":{",sizeof(ds_ball));
    FIELD(ds_surface,pixels);FIELD(ds_surface,width);FIELD(ds_surface,height);FIELD(ds_surface,pitch_words);
    FIELD(ds_surface,span_words);FIELD(ds_surface,rgbx);
    printf("\"end\":%zu}}\n",sizeof(ds_surface));
    return 0;
}
