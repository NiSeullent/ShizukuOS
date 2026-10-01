/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_CSS_TEST_SUPPORT_H
#define M98_CSS_TEST_SUPPORT_H
#include "m98_css_variables.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if(!(x)){fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);} } while(0)
typedef struct {size_t calls,fail,live;} heap;
static void *allocate(void *v,size_t n){heap *h=(heap *)v;void *p;h->calls++;if(h->fail&&h->calls==h->fail)return 0;p=malloc(n);if(p)h->live++;return p;}
static void deallocate(void *v,void *p){heap *h=(heap *)v;if(p){CHECK(h->live>0);h->live--;free(p);}}
static m98_css_allocator allocator(heap *h){m98_css_allocator a={h,allocate,deallocate};return a;}
static size_t utf16(const char *s,uint16_t *p){size_t n=0;while(*s)p[n++]=(unsigned char)*s++;return n;}
static m98_css_stream *lex(heap *h,const char *s){uint16_t p[M98_CSS_INPUT_MAX];m98_css_stream *o=0;m98_css_allocator a=allocator(h);size_t n=utf16(s,p);CHECK(m98_css_tokenize(p,n,&a,&o)==0);return o;}
static int identical(const m98_css_stream *a,const m98_css_stream *b){size_t i=0,j=0,k;const uint32_t *x,*y;
 while(i<m98_css_count(a)&&j<m98_css_count(b)){const m98_css_token *u=m98_css_at(a,i),*v=m98_css_at(b,j);
  if(u->kind!=v->kind||u->flags!=v->flags)return 0;
  if(u->kind==M98_CSS_WS){while(i<m98_css_count(a)&&m98_css_at(a,i)->kind==M98_CSS_WS)i++;while(j<m98_css_count(b)&&m98_css_at(b,j)->kind==M98_CSS_WS)j++;continue;}
  if(u->kind==M98_CSS_DELIM&&u->delim!=v->delim)return 0;
  if(u->value_length!=v->value_length||u->number_length!=v->number_length)return 0;
  x=m98_css_value(a,u);y=m98_css_value(b,v);for(k=0;k<u->value_length;k++)if(x[k]!=y[k])return 0;
  x=m98_css_number(a,u);y=m98_css_number(b,v);for(k=0;k<u->number_length;k++)if(x[k]!=y[k])return 0;
  i++;j++;
 }return i==m98_css_count(a)&&j==m98_css_count(b);
}
static void roundtrip(heap *h,const m98_css_stream *o){uint16_t *text;size_t n=0;int r;m98_css_stream *other=0;m98_css_allocator a=allocator(h);
 CHECK(m98_css_serialize(o,0,0,&n)==0);CHECK(n<=M98_CSS_INPUT_MAX);
 text=(uint16_t *)malloc((n+1)*sizeof(uint16_t));CHECK(text!=0);
 r=m98_css_serialize(o,text,n,&n);CHECK(r==0);CHECK(m98_css_tokenize(text,n,&a,&other)==0);CHECK(identical(o,other));m98_css_destroy(&other);free(text);
}
static inline void expected(heap *h,const m98_css_stream *o,const char *s){m98_css_stream *e=lex(h,s);CHECK(o!=0);CHECK(identical(o,e));roundtrip(h,o);m98_css_destroy(&e);}
#endif
