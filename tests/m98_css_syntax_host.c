/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_css_test_support.h"
#include "css_selected_vectors.h"
static void vector_tests(heap *h){size_t i,j,k;m98_css_allocator a=allocator(h);
 for(i=0;i<sizeof(syntax_vectors)/sizeof(syntax_vectors[0]);i++){const css_syntax_vector *v=syntax_vectors+i;m98_css_stream *o=0;
  CHECK(m98_css_tokenize(v->input,v->units,&a,&o)==0);CHECK(m98_css_count(o)==v->count);CHECK(m98_css_errors(o)==v->errors);
  for(j=0;j<v->count;j++){const m98_css_token *t=m98_css_at(o,j);const css_expected_token *e=v->tokens+j;const uint32_t *p=m98_css_value(o,t),*n=m98_css_number(o,t);
   CHECK(t->kind==e->kind);CHECK(t->flags==e->flags);CHECK(t->value_length==e->value_length);CHECK(t->number_length==e->number_length);CHECK(t->delim==e->delim);
   for(k=0;k<t->value_length;k++)CHECK(p[k]==e->value[k]);for(k=0;k<t->number_length;k++)CHECK(n[k]==e->number[k]);
  }
  if(v->serialize)roundtrip(h,o);m98_css_destroy(&o);
 }
}
static void preprocessing(heap *h){m98_css_allocator a=allocator(h);m98_css_stream *o=0;const uint32_t *p;const m98_css_token *t;
 uint16_t input[]={13,10,12,13,9,0,0xd800,'A',0xdc00,0xd83d,0xde00};
 CHECK(m98_css_tokenize(input,sizeof(input)/sizeof(input[0]),&a,&o)==0);CHECK(m98_css_replacements(o)==3);CHECK(m98_css_count(o)==2);
 t=m98_css_at(o,0);p=m98_css_value(o,t);CHECK(t->kind==M98_CSS_WS&&t->value_length==4);CHECK(p[0]==10&&p[1]==10&&p[2]==10&&p[3]==9);
 t=m98_css_at(o,1);p=m98_css_value(o,t);CHECK(t->kind==M98_CSS_IDENT&&t->value_length==5);CHECK(p[0]==0xfffd&&p[1]==0xfffd&&p[2]=='A'&&p[3]==0xfffd&&p[4]==0x1f600);roundtrip(h,o);m98_css_destroy(&o);
}
static void recovery(heap *h){m98_css_stream *o=lex(h,"\"a\nb;url(x y)z/*oops");size_t n=123;uint16_t output[8];
 CHECK(m98_css_errors(o)==3);CHECK(m98_css_at(o,0)->kind==M98_CSS_BAD_STRING);CHECK(m98_css_at(o,1)->kind==M98_CSS_WS);
 CHECK(m98_css_at(o,4)->kind==M98_CSS_BAD_URL);CHECK(m98_css_ascii(o,5,"z",0));
 memset(output,0x55,sizeof(output));CHECK(m98_css_serialize(o,output,8,&n)==M98_CSS_UNSUPPORTED);CHECK(n==123&&output[0]==0x5555);m98_css_destroy(&o);
 o=lex(h,"'a\\\nb' url('x') url(foo\\)bar) #123 #\\31 x 1e2em 1\\65 2");roundtrip(h,o);m98_css_destroy(&o);
 o=lex(h," /**/ ");CHECK(m98_css_count(o)==2);roundtrip(h,o);m98_css_destroy(&o);
}
static void pairs(heap *h){const char *items[]={"foo","bar()","url(bar)","-","123","123%","123em","-->","()","@foo","#foo","#123","#","@",".","+","/","*","%","url('x')","'abc'"};size_t i,j;
 for(i=0;i<sizeof(items)/sizeof(items[0]);i++)for(j=0;j<sizeof(items)/sizeof(items[0]);j++){m98_css_stream *a=lex(h,items[i]),*b=lex(h,items[j]),*o=0;m98_css_allocator x=allocator(h);size_t k;
  CHECK(m98_css_empty(&x,&o)==0);for(k=0;k<m98_css_count(a);k++)CHECK(m98_css_append(o,a,k)==0);for(k=0;k<m98_css_count(b);k++)CHECK(m98_css_append(o,b,k)==0);roundtrip(h,o);m98_css_destroy(&o);m98_css_destroy(&a);m98_css_destroy(&b);
 }
}
static void bounds_and_faults(heap *h){m98_css_allocator a=allocator(h);m98_css_stream *o=0,*sentinel=(m98_css_stream *)(uintptr_t)1;uint16_t *p;size_t count,i,base,n=0;uint16_t output[2]={0x1234,0x5678};
 o=lex(h,"1 em");CHECK(m98_css_serialize(o,output,2,&n)==M98_CSS_LIMIT);CHECK(n>2&&output[0]==0x1234&&output[1]==0x5678);m98_css_destroy(&o);
 CHECK(m98_css_tokenize(0,1,&a,&sentinel)==M98_CSS_ARGUMENT&&sentinel==(m98_css_stream *)(uintptr_t)1);
 CHECK(m98_css_tokenize(0,M98_CSS_INPUT_MAX+1,&a,&sentinel)==M98_CSS_ARGUMENT);
 p=(uint16_t *)malloc((M98_CSS_INPUT_MAX+1)*sizeof(*p));CHECK(p!=0);for(i=0;i<M98_CSS_INPUT_MAX+1;i++)p[i]='x';
 CHECK(m98_css_tokenize(p,M98_CSS_INPUT_MAX+1,&a,&sentinel)==M98_CSS_LIMIT);CHECK(sentinel==(m98_css_stream *)(uintptr_t)1);
 for(i=0;i<M98_CSS_TOKEN_MAX+1;i++)p[i]=';';CHECK(m98_css_tokenize(p,M98_CSS_TOKEN_MAX+1,&a,&sentinel)==M98_CSS_LIMIT);CHECK(sentinel==(m98_css_stream *)(uintptr_t)1);free(p);
 base=h->calls;o=lex(h,"foo bar #abc 123px url(a) 'str' (x) /*end*/");count=h->calls-base;m98_css_destroy(&o);
 for(i=1;i<=count;i++){uint16_t text[100];size_t units=utf16("foo bar #abc 123px url(a) 'str' (x) /*end*/",text);h->fail=h->calls+i;CHECK(m98_css_tokenize(text,units,&a,&sentinel)==M98_CSS_MEMORY);CHECK(sentinel==(m98_css_stream *)(uintptr_t)1);CHECK(h->live==0);h->fail=0;}
 m98_css_destroy(&o);m98_css_destroy(0);CHECK(h->live==0);
}
static void append_ownership(heap *h){m98_css_allocator a=allocator(h);m98_css_stream *src=lex(h,"abc"),*dst=0,*white=lex(h," ");size_t i;
 CHECK(m98_css_empty(&a,&dst)==0);CHECK(m98_css_append(dst,dst,0)==M98_CSS_ARGUMENT);
 CHECK(m98_css_literal(dst,M98_CSS_DELIM,'x')==M98_CSS_ARGUMENT);CHECK(m98_css_literal(dst,M98_CSS_RPAREN,')')==M98_CSS_ARGUMENT);
 h->fail=h->calls+1;CHECK(m98_css_append(dst,src,0)==M98_CSS_MEMORY);CHECK(m98_css_count(dst)==0);h->fail=0;
 /* Next failure occurs after token-array growth succeeded, before pool commit. */
 h->fail=h->calls+2;CHECK(m98_css_append(dst,src,0)==M98_CSS_MEMORY);CHECK(m98_css_count(dst)==0);h->fail=0;
 CHECK(m98_css_append(dst,src,0)==0);m98_css_destroy(&src);expected(h,dst,"abc");m98_css_destroy(&dst);
 CHECK(m98_css_empty(&a,&dst)==0);for(i=0;i<70;i++)CHECK(m98_css_append(dst,white,0)==0);CHECK(m98_css_count(dst)==1);CHECK(m98_css_at(dst,0)->value_length==70);roundtrip(h,dst);m98_css_destroy(&white);m98_css_destroy(&dst);CHECK(h->live==0);
}
int main(void){heap h={0};vector_tests(&h);preprocessing(&h);recovery(&h);pairs(&h);bounds_and_faults(&h);append_ownership(&h);CHECK(h.live==0);printf("PASS CSS syntax: %u assertions; no native/style/paint claim\n",checks);return 0;}
