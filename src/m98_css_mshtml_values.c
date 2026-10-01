/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_css_mshtml_values.h"
static int access_ok(const m98_css_value_access *a){
 return a&&a->count&&a->at&&a->value&&a->number&&a->ascii;
}
static const m98_css_token *one(const m98_css_value_access *a,const m98_css_stream *s,size_t *index){
 size_t first=0,last=a->count(s);const m98_css_token *t;
 while(first<last){t=a->at(s,first);if(!t)return 0;if(t->kind!=M98_CSS_WS)break;first++;}
 while(last>first){t=a->at(s,last-1);if(!t)return 0;if(t->kind!=M98_CSS_WS)break;last--;}
 if(last!=first+1)return 0;
 *index=first;return a->at(s,first);
}
int m98_css_mshtml_width(const m98_css_value_access *a,const m98_css_stream *s,int *out){
 const m98_css_token *t;const uint32_t *digits;size_t index=0,i=0;unsigned n=0;int negative=0;
 if(!access_ok(a)||!s||!out)return M98_CSS_ARGUMENT;
 t=one(a,s,&index);if(!t)return M98_CSS_UNSUPPORTED;
 if(t->kind!=M98_CSS_DIMENSION&&t->kind!=M98_CSS_NUMBER)return M98_CSS_UNSUPPORTED;
 if(t->kind==M98_CSS_DIMENSION&&!a->ascii(s,index,"px",1))return M98_CSS_UNSUPPORTED;
 if(!(t->flags&M98_CSS_INTEGER))return M98_CSS_UNSUPPORTED;
 digits=a->number(s,t);if(!digits||!t->number_length)return M98_CSS_INVALID;
 if(digits[0]=='-'||digits[0]=='+'){negative=digits[0]=='-';i++;}
 if(i==t->number_length)return M98_CSS_INVALID;
 if(negative){
  int nonzero=0;
  for(;i<t->number_length;i++){
   if(digits[i]<'0'||digits[i]>'9')return M98_CSS_UNSUPPORTED;
   if(digits[i]!='0')nonzero=1;
  }
  if(nonzero)return M98_CSS_INVALID;
  *out=0;return M98_CSS_OK;
 }
 for(;i<t->number_length;i++){
  if(digits[i]<'0'||digits[i]>'9')return M98_CSS_UNSUPPORTED;
  if(n>1024/10||(n==1024/10&&digits[i]-'0'>1024%10))return M98_CSS_LIMIT;
  n=n*10+digits[i]-'0';
 }
 if(t->kind==M98_CSS_NUMBER&&n)return M98_CSS_INVALID;
 *out=(int)n;return M98_CSS_OK;
}
static int hex(uint32_t c){
 if(c>='0'&&c<='9')return (int)(c-'0');
 if(c>='a'&&c<='f')return (int)(c-'a'+10);
 if(c>='A'&&c<='F')return (int)(c-'A'+10);
 return -1;
}
int m98_css_mshtml_color(const m98_css_value_access *a,const m98_css_stream *s,uint16_t out[7]){
 const m98_css_token *t;const uint32_t *v;size_t index=0,i;uint16_t value[7];int h;
 static const char digits[]="0123456789abcdef";
 if(!access_ok(a)||!s||!out)return M98_CSS_ARGUMENT;
 t=one(a,s,&index);if(!t||t->kind!=M98_CSS_HASH)return M98_CSS_UNSUPPORTED;
 if(t->value_length!=3&&t->value_length!=6)return M98_CSS_UNSUPPORTED;
 v=a->value(s,t);if(!v)return M98_CSS_INVALID;
 value[0]='#';
 for(i=0;i<t->value_length;i++){
  h=hex(v[i]);if(h<0)return M98_CSS_INVALID;
  if(t->value_length==3)value[1+2*i]=value[2+2*i]=(uint16_t)digits[h];
  else value[1+i]=(uint16_t)digits[h];
 }
 for(i=0;i<7;i++)out[i]=value[i];
 return M98_CSS_OK;
}
