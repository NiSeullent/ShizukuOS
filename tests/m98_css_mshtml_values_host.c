/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_css_mshtml_values.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line%d %s\n",__LINE__,#x);exit(1);}}while(0)
static void *allocate(void *u,size_t n){(void)u;return malloc(n);}
static void release(void *u,void *p){(void)u;free(p);}
static const m98_css_allocator allocator={0,allocate,release};
static const m98_css_value_access accessors={m98_css_count,m98_css_at,m98_css_value,m98_css_number,m98_css_ascii};
static m98_css_stream *tokens(const char *text){uint16_t units[256];size_t n=strlen(text),i;m98_css_stream *s=0;
 CHECK(n<256);for(i=0;i<n;i++)units[i]=(unsigned char)text[i];CHECK(m98_css_tokenize(units,n,&allocator,&s)==0);return s;}
static void width(const char *text,int status,int expected){m98_css_stream *s=tokens(text);int result=-77;
 CHECK(m98_css_mshtml_width(&accessors,s,&result)==status);CHECK(result==(status? -77:expected));m98_css_destroy(&s);CHECK(!s);}
static void color(const char *text,int status,const char *expected){m98_css_stream *s=tokens(text);uint16_t result[7];size_t i;
 for(i=0;i<7;i++)result[i]=0xabcd;
 CHECK(m98_css_mshtml_color(&accessors,s,result)==status);
 for(i=0;i<7;i++)CHECK(result[i]==(status?0xabcd:(uint16_t)(unsigned char)expected[i]));
 m98_css_destroy(&s);CHECK(!s);}
int main(void){
 width("168px",0,168);width(" +00168PX ",0,168);width("0",0,0);width("-0px",0,0);width("1024px",0,1024);
 width("-1px",M98_CSS_INVALID,0);width("1",M98_CSS_INVALID,0);width("1025px",M98_CSS_LIMIT,0);
 width("-1025px",M98_CSS_INVALID,0);width("-999999999999999999999999px",M98_CSS_INVALID,0);
 width("999999999999999999999999px",M98_CSS_LIMIT,0);width("1.5px",M98_CSS_UNSUPPORTED,0);
 width("1e2px",M98_CSS_UNSUPPORTED,0);width("12%",M98_CSS_UNSUPPORTED,0);width("2em",M98_CSS_UNSUPPORTED,0);
 width("calc(1px + 1px)",M98_CSS_UNSUPPORTED,0);width("initial",M98_CSS_UNSUPPORTED,0);width("1px 2px",M98_CSS_UNSUPPORTED,0);
 width("",M98_CSS_UNSUPPORTED,0);width("168\\70 x",0,168);
 color("#10365e",0,"#10365e");color(" #AbC ",0,"#aabbcc");color("#2F7A3C",0,"#2f7a3c");
 color("#1234",M98_CSS_UNSUPPORTED,0);color("#11223344",M98_CSS_UNSUPPORTED,0);
 color("#12g",M98_CSS_INVALID,0);color("red",M98_CSS_UNSUPPORTED,0);color("rgb(0 0 0)",M98_CSS_UNSUPPORTED,0);
 color("#123 #456",M98_CSS_UNSUPPORTED,0);color("",M98_CSS_UNSUPPORTED,0);
 {int out=19;uint16_t c[7]={0};m98_css_value_access missing=accessors;missing.number=0;
  CHECK(m98_css_mshtml_width(0,0,&out)==M98_CSS_ARGUMENT&&out==19);
  CHECK(m98_css_mshtml_width(&missing,0,&out)==M98_CSS_ARGUMENT&&out==19);
  CHECK(m98_css_mshtml_color(&accessors,0,c)==M98_CSS_ARGUMENT);}
 printf("PASS genuine CSS token consumer: %u assertions; no MSHTML/native/complete property grammar claim\n",checks);return 0;
}
