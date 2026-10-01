/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded CSS Syntax3 implementation; no upstream engine code copied.
 * Algorithms: https://drafts.csswg.org/css-syntax-3/ (accessed 2026-10-01). */
#include "m98_css_syntax.h"
#include <string.h>
struct m98_css_stream { m98_css_allocator a; m98_css_token *t;
 uint32_t *p; size_t nt,ct,np,cp; uint32_t errors,replacements; };
typedef struct { uint32_t *s; size_t n,i; m98_css_stream *o; int error; } lexer;
static int allocator_ok(const m98_css_allocator *a) { return a&&a->alloc&&a->free; }
static int grow(m98_css_stream *o,int tokens,size_t needed) {
 size_t cap=tokens?o->ct:o->cp,limit=tokens?M98_CSS_TOKEN_MAX:M98_CSS_POOL_MAX;
 size_t width=tokens?sizeof(m98_css_token):sizeof(uint32_t),used=tokens?o->nt:o->np;
 void *old=tokens?(void *)o->t:(void *)o->p,*fresh;
 if(needed>limit)return M98_CSS_LIMIT;
 if(needed<=cap)return 0;
 if(!cap)cap=tokens?16:64;
 while(cap<needed)cap=cap>limit/2?limit:cap*2;
 fresh=o->a.alloc(o->a.user,cap*width);
 if(!fresh)return M98_CSS_MEMORY;
 if(used)memcpy(fresh,old,used*width);
 if(old)o->a.free(o->a.user,old);
 if(tokens){o->t=(m98_css_token *)fresh;o->ct=cap;}
 else{o->p=(uint32_t *)fresh;o->cp=cap;}
 return 0;
}
int m98_css_empty(const m98_css_allocator *a,m98_css_stream **out) {
 m98_css_stream *o;
 if(!allocator_ok(a)||!out)return M98_CSS_ARGUMENT;
 o=(m98_css_stream *)a->alloc(a->user,sizeof(*o));
 if(!o)return M98_CSS_MEMORY;
 memset(o,0,sizeof(*o));o->a=*a;*out=o;return 0;
}
void m98_css_destroy(m98_css_stream **p) {
 m98_css_stream *o; m98_css_allocator a;
 if(!p||!*p)return;
 o=*p;a=o->a;*p=0;
 if(o->t)a.free(a.user,o->t);
 if(o->p)a.free(a.user,o->p);
 a.free(a.user,o);
}
size_t m98_css_count(const m98_css_stream *o){return o?o->nt:0;}
const m98_css_token *m98_css_at(const m98_css_stream *o,size_t i){return o&&i<o->nt?o->t+i:0;}
const uint32_t *m98_css_value(const m98_css_stream *o,const m98_css_token *t){return o&&t&&t->value_length?o->p+t->value_offset:0;}
const uint32_t *m98_css_number(const m98_css_stream *o,const m98_css_token *t){return o&&t&&t->number_length?o->p+t->number_offset:0;}
uint32_t m98_css_errors(const m98_css_stream *o){return o?o->errors:0;}
uint32_t m98_css_replacements(const m98_css_stream *o){return o?o->replacements:0;}
int m98_css_append(m98_css_stream *o,const m98_css_stream *s,size_t i) {
 const m98_css_token *t; m98_css_token copy; size_t n; int r;
 if(!o||!s||o==s||i>=s->nt)return M98_CSS_ARGUMENT;
 t=s->t+i;copy=*t;n=(size_t)t->value_length+t->number_length;
 if(t->kind==M98_CSS_WS&&o->nt&&o->t[o->nt-1].kind==M98_CSS_WS){
  if((r=grow(o,0,o->np+n)))return r;
  if(n)memcpy(o->p+o->np,s->p+t->value_offset,n*sizeof(uint32_t));
  o->np+=n;o->t[o->nt-1].value_length+=(uint32_t)n;return 0;
 }
 if((r=grow(o,1,o->nt+1))||(r=grow(o,0,o->np+n)))return r;
 copy.value_offset=(uint32_t)o->np;
 if(t->value_length)memcpy(o->p+o->np,s->p+t->value_offset,t->value_length*sizeof(uint32_t));
 o->np+=t->value_length;copy.number_offset=(uint32_t)o->np;
 if(t->number_length)memcpy(o->p+o->np,s->p+t->number_offset,t->number_length*sizeof(uint32_t));
 o->np+=t->number_length;o->t[o->nt++]=copy;return 0;
}
int m98_css_literal(m98_css_stream *o,uint32_t kind,uint32_t delim) {
 m98_css_token t;int r;
 if(!o||delim||(kind!=M98_CSS_RPAREN&&kind!=M98_CSS_RBRACKET&&kind!=M98_CSS_RBRACE))return M98_CSS_ARGUMENT;
 if((r=grow(o,1,o->nt+1)))return r;
 memset(&t,0,sizeof(t));t.kind=kind;t.delim=delim;o->t[o->nt++]=t;return 0;
}
static uint32_t at(lexer *l,size_t i){return i<l->n?l->s[i]:0;}
static int ws(uint32_t c){return c==9||c==10||c==32;}
static int digit(uint32_t c){return c>='0'&&c<='9';}
static int hex(uint32_t c){return digit(c)||(c>='a'&&c<='f')||(c>='A'&&c<='F');}
static uint32_t lower(uint32_t c){return c>='A'&&c<='Z'?c+32:c;}
static int start(uint32_t c){return (lower(c)>='a'&&lower(c)<='z')||c=='_'||c>=128;}
static int name(uint32_t c){return start(c)||digit(c)||c=='-';}
static int escape(lexer *l,size_t i){return at(l,i)=='\\'&&at(l,i+1)!=10;}
static int ident(lexer *l,size_t i){uint32_t c=at(l,i);return c=='-'?(start(at(l,i+1))||at(l,i+1)=='-'||escape(l,i+1)):start(c)||escape(l,i);}
static int numeric(lexer *l,size_t i){uint32_t c=at(l,i);if(c=='+'||c=='-')i++;return digit(at(l,i))||(at(l,i)=='.'&&digit(at(l,i+1)));}
static void put(lexer *l,uint32_t c){int r;if(l->error)return;if((r=grow(l->o,0,l->o->np+1))){l->error=r;return;}l->o->p[l->o->np++]=c;}
static uint32_t escaped(lexer *l) {
 uint32_t c,v=0;unsigned k=0;
 l->i++;c=at(l,l->i);
 if(!c){l->o->errors++;return 0xfffd;}
 if(hex(c)){
  while(k<6&&hex(at(l,l->i))){c=lower(at(l,l->i++));v=v*16+(digit(c)?c-'0':c-'a'+10);k++;}
  if(ws(at(l,l->i)))l->i++;
  return !v||v>0x10ffff||(v>=0xd800&&v<=0xdfff)?0xfffd:v;
 }
 l->i++;return c;
}
static void consume_name(lexer *l){while(l->i<l->n){uint32_t c=at(l,l->i);if(name(c)){put(l,c);l->i++;}else if(escape(l,l->i))put(l,escaped(l));else break;}}
static void bad_url(lexer *l){while(l->i<l->n){uint32_t c=at(l,l->i);if(c==')'){l->i++;break;}if(escape(l,l->i))(void)escaped(l);else l->i++;}}
static void url(lexer *l,m98_css_token *t) {
 while(ws(at(l,l->i)))l->i++;
 t->value_offset=(uint32_t)l->o->np;
 for(;;){uint32_t c=at(l,l->i);
  if(c==')'){l->i++;break;}
  if(!c){l->o->errors++;break;}
  if(ws(c)){
   while(ws(at(l,l->i)))l->i++;
   if(at(l,l->i)==')'){l->i++;break;}
   if(!at(l,l->i)){l->o->errors++;break;}
   t->kind=M98_CSS_BAD_URL;l->o->errors++;bad_url(l);break;
  }
  if(c=='"'||c=='\''||c=='('||c<=8||c==11||(c>=14&&c<=31)||c==127){t->kind=M98_CSS_BAD_URL;l->o->errors++;bad_url(l);break;}
  if(c=='\\'){if(escape(l,l->i))put(l,escaped(l));else{t->kind=M98_CSS_BAD_URL;l->o->errors++;bad_url(l);break;}}
  else{put(l,c);l->i++;}
 }
 t->value_length=t->kind==M98_CSS_BAD_URL?0:(uint32_t)l->o->np-t->value_offset;
}
static void string(lexer *l,m98_css_token *t,uint32_t quote) {
 l->i++;t->value_offset=(uint32_t)l->o->np;
 for(;;){uint32_t c=at(l,l->i);
  if(c==quote){l->i++;break;}
  if(!c){l->o->errors++;break;}
  if(c==10){t->kind=M98_CSS_BAD_STRING;l->o->errors++;break;}
  if(c=='\\'){
   if(l->i+1>=l->n){l->i++;continue;}
   if(at(l,l->i+1)==10){l->i+=2;continue;}
   put(l,escaped(l));
  }else{put(l,c);l->i++;}
 }
 t->value_length=t->kind==M98_CSS_BAD_STRING?0:(uint32_t)l->o->np-t->value_offset;
}
static void number(lexer *l,m98_css_token *t) {
 size_t begin=l->i,i;uint32_t c;
 t->flags=M98_CSS_INTEGER;t->kind=M98_CSS_NUMBER;
 if(at(l,l->i)=='+'||at(l,l->i)=='-')l->i++;
 while(digit(at(l,l->i)))l->i++;
 if(at(l,l->i)=='.'&&digit(at(l,l->i+1))){t->flags=0;l->i+=2;while(digit(at(l,l->i)))l->i++;}
 c=lower(at(l,l->i));i=l->i+1;
 if(at(l,i)=='+'||at(l,i)=='-')i++;
 if(c=='e'&&digit(at(l,i))){t->flags=0;l->i=i+1;while(digit(at(l,l->i)))l->i++;}
 t->number_offset=(uint32_t)l->o->np;
 for(i=begin;i<l->i;i++)put(l,at(l,i));
 t->number_length=(uint32_t)l->o->np-t->number_offset;
 if(ident(l,l->i)){t->kind=M98_CSS_DIMENSION;t->value_offset=(uint32_t)l->o->np;consume_name(l);t->value_length=(uint32_t)l->o->np-t->value_offset;}
 else if(at(l,l->i)=='%'){t->kind=M98_CSS_PERCENTAGE;l->i++;}
}
int m98_css_ascii(const m98_css_stream *o,size_t i,const char *s,int insensitive) {
 const m98_css_token *t=m98_css_at(o,i);size_t k;
 if(!t||!s)return 0;
 for(k=0;k<t->value_length;k++){uint32_t c=o->p[t->value_offset+k],d=(unsigned char)s[k];if(!d||(insensitive?lower(c)!=lower(d):c!=d))return 0;}
 return s[k]==0;
}
static void token(lexer *l) {
 m98_css_token t;uint32_t c;size_t i;int r;
 memset(&t,0,sizeof(t));c=at(l,l->i);
 if(ws(c)){t.kind=M98_CSS_WS;t.value_offset=(uint32_t)l->o->np;while(ws(at(l,l->i)))put(l,at(l,l->i++));t.value_length=(uint32_t)l->o->np-t.value_offset;}
 else if(c=='"'||c=='\''){t.kind=M98_CSS_STRING;string(l,&t,c);}
 else if(c=='<'&&at(l,l->i+1)=='!'&&at(l,l->i+2)=='-'&&at(l,l->i+3)=='-'){t.kind=M98_CSS_CDO;l->i+=4;}
 else if(c=='-'&&at(l,l->i+1)=='-'&&at(l,l->i+2)=='>'){t.kind=M98_CSS_CDC;l->i+=3;}
 else if(numeric(l,l->i))number(l,&t);
 else if(c=='#'&&(name(at(l,l->i+1))||escape(l,l->i+1))){t.kind=M98_CSS_HASH;if(ident(l,l->i+1))t.flags=M98_CSS_HASH_ID;l->i++;t.value_offset=(uint32_t)l->o->np;consume_name(l);t.value_length=(uint32_t)l->o->np-t.value_offset;}
 else if(c=='@'&&ident(l,l->i+1)){t.kind=M98_CSS_AT;l->i++;t.value_offset=(uint32_t)l->o->np;consume_name(l);t.value_length=(uint32_t)l->o->np-t.value_offset;}
 else if(ident(l,l->i)){
  t.kind=M98_CSS_IDENT;t.value_offset=(uint32_t)l->o->np;consume_name(l);t.value_length=(uint32_t)l->o->np-t.value_offset;
  if(at(l,l->i)=='('){l->i++;t.kind=M98_CSS_FUNCTION;
   if(t.value_length==3&&lower(l->o->p[t.value_offset])=='u'&&lower(l->o->p[t.value_offset+1])=='r'&&lower(l->o->p[t.value_offset+2])=='l'){
    i=l->i;while(ws(at(l,i)))i++;
    if(at(l,i)!='"'&&at(l,i)!='\''){t.kind=M98_CSS_URL;url(l,&t);}
   }
  }
 }else{
  l->i++;t.delim=c;
  switch(c){case ':':t.kind=M98_CSS_COLON;break;case ';':t.kind=M98_CSS_SEMICOLON;break;case ',':t.kind=M98_CSS_COMMA;break;
  case '(':t.kind=M98_CSS_LPAREN;break;case ')':t.kind=M98_CSS_RPAREN;break;case '[':t.kind=M98_CSS_LBRACKET;break;case ']':t.kind=M98_CSS_RBRACKET;break;case '{':t.kind=M98_CSS_LBRACE;break;case '}':t.kind=M98_CSS_RBRACE;break;default:t.kind=M98_CSS_DELIM;if(c=='\\')l->o->errors++;break;}
 }
 if(l->error)return;
 if((r=grow(l->o,1,l->o->nt+1))){l->error=r;return;}l->o->t[l->o->nt++]=t;
}
int m98_css_tokenize(const uint16_t *input,size_t n,const m98_css_allocator *a,m98_css_stream **out) {
 lexer l;m98_css_stream *o=0;size_t i=0,k=0;int r;uint32_t c;
 if(!out||(!input&&n)||!allocator_ok(a))return M98_CSS_ARGUMENT;
 if(n>M98_CSS_INPUT_MAX)return M98_CSS_LIMIT;
 if((r=m98_css_empty(a,&o)))return r;
 memset(&l,0,sizeof(l));l.o=o;l.s=(uint32_t *)a->alloc(a->user,(n+1)*sizeof(uint32_t));
 if(!l.s){m98_css_destroy(&o);return M98_CSS_MEMORY;}
 while(i<n){c=input[i++];
  if(c==13){if(i<n&&input[i]==10)i++;c=10;}
  else if(c==12)c=10;
  else if(c>=0xd800&&c<=0xdbff&&i<n&&input[i]>=0xdc00&&input[i]<=0xdfff)c=0x10000+((c-0xd800)<<10)+(input[i++]-0xdc00);
  else if(!c||(c>=0xd800&&c<=0xdfff)){c=0xfffd;o->replacements++;}
  l.s[k++]=c;
 }
 l.n=k;
 while(l.i<l.n&&!l.error){
  if(at(&l,l.i)=='/'&&at(&l,l.i+1)=='*'){
   l.i+=2;while(l.i<l.n&&!(at(&l,l.i)=='*'&&at(&l,l.i+1)=='/'))l.i++;
   if(l.i==l.n)o->errors++;else l.i+=2;
  }else token(&l);
 }
 a->free(a->user,l.s);
 if(l.error){r=l.error;m98_css_destroy(&o);return r;}
 *out=o;return 0;
}
typedef struct {uint16_t *p;size_t n;int error;} writer;
static void emit(writer *w,uint32_t c){if(c>0xffff){c-=0x10000;if(w->p){w->p[w->n]=(uint16_t)(0xd800+(c>>10));w->p[w->n+1]=(uint16_t)(0xdc00+(c&1023));}w->n+=2;}else{if(w->p)w->p[w->n]=(uint16_t)c;w->n++;}}
static void ascii_emit(writer *w,const char *s){while(*s)emit(w,(unsigned char)*s++);}
static void escape_emit(writer *w,uint32_t c){char digits[6];unsigned n=0;emit(w,'\\');do{digits[n++]="0123456789abcdef"[c&15];c>>=4;}while(c);while(n)emit(w,(unsigned char)digits[--n]);emit(w,' ');}
static void serialize_pass(const m98_css_stream *o,writer *w) {
 size_t i,k;int previous=0;
 for(i=0;i<o->nt;i++){const m98_css_token *t=o->t+i;const uint32_t *v=m98_css_value(o,t),*n=m98_css_number(o,t);
  if(t->kind==M98_CSS_BAD_STRING||t->kind==M98_CSS_BAD_URL){w->error=M98_CSS_UNSUPPORTED;return;}
  /* A conservative comment separator preserves all non-whitespace adjacency,
   * including NUMBER + IDENT after var substitution. It has no parser meaning. */
  if(previous&&t->kind!=M98_CSS_WS)ascii_emit(w,"/**/");
  /* A function token already ends in '('. In particular a comment before the
   * string following url( would change the lexical token to a bad URL. */
  previous=t->kind!=M98_CSS_WS&&t->kind!=M98_CSS_FUNCTION;
  switch(t->kind){
  case M98_CSS_WS:for(k=0;k<t->value_length;k++)emit(w,v[k]);break;
  case M98_CSS_NUMBER:case M98_CSS_PERCENTAGE:case M98_CSS_DIMENSION:
   for(k=0;k<t->number_length;k++)emit(w,n[k]);
   if(t->kind==M98_CSS_PERCENTAGE)emit(w,'%');
   if(t->kind==M98_CSS_DIMENSION)for(k=0;k<t->value_length;k++)escape_emit(w,v[k]);
   break;
  case M98_CSS_IDENT:case M98_CSS_FUNCTION:case M98_CSS_AT:case M98_CSS_HASH:
   if(t->kind==M98_CSS_AT)emit(w,'@');
   if(t->kind==M98_CSS_HASH)emit(w,'#');
   for(k=0;k<t->value_length;k++){if(t->kind==M98_CSS_HASH&&!(t->flags&M98_CSS_HASH_ID)&&(digit(v[k])||(k==0&&v[k]=='-')))emit(w,v[k]);else escape_emit(w,v[k]);}
   if(t->kind==M98_CSS_FUNCTION)emit(w,'(');
   break;
  case M98_CSS_STRING:emit(w,'"');for(k=0;k<t->value_length;k++)escape_emit(w,v[k]);emit(w,'"');break;
  case M98_CSS_URL:ascii_emit(w,"url(");for(k=0;k<t->value_length;k++)escape_emit(w,v[k]);emit(w,')');break;
  case M98_CSS_CDO:ascii_emit(w,"<!--");break;case M98_CSS_CDC:ascii_emit(w,"-->");break;
  case M98_CSS_COLON:emit(w,':');break;case M98_CSS_SEMICOLON:emit(w,';');break;case M98_CSS_COMMA:emit(w,',');break;
  case M98_CSS_LPAREN:emit(w,'(');break;case M98_CSS_RPAREN:emit(w,')');break;case M98_CSS_LBRACKET:emit(w,'[');break;case M98_CSS_RBRACKET:emit(w,']');break;case M98_CSS_LBRACE:emit(w,'{');break;case M98_CSS_RBRACE:emit(w,'}');break;
  case M98_CSS_DELIM:emit(w,t->delim);if(t->delim=='\\')emit(w,10);break;
  default:w->error=M98_CSS_ARGUMENT;return;
  }
 }
}
int m98_css_serialize(const m98_css_stream *o,uint16_t *p,size_t cap,size_t *units) {
 writer w;if(!o||!units||(!p&&cap))return M98_CSS_ARGUMENT;
 memset(&w,0,sizeof(w));serialize_pass(o,&w);if(w.error)return w.error;
 *units=w.n;if(!p)return 0;if(cap<w.n)return M98_CSS_LIMIT;
 w.p=p;w.n=0;serialize_pass(o,&w);return w.error;
}
