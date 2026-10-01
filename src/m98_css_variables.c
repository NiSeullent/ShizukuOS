/* SPDX-License-Identifier: GPL-2.0-only
 * Original core, current CSS Variables1 + CSS Values5 property replacement.
 * No DOM, selector cascade, property grammar, style setter or painting claimed. */
#include "m98_css_variables.h"
#include <string.h>
typedef struct { m98_css_stream *name,*specified,*computed;
 unsigned state,invalid,cycle,local; } property;
struct m98_css_snapshot {m98_css_allocator a;property p[M98_CSS_PROPERTY_MAX];size_t n;};
typedef struct {m98_css_snapshot *s;const m98_css_snapshot *parent;size_t stack[M98_CSS_PROPERTY_MAX],depth;int error;} evaluator;
static int same(const m98_css_stream *a,size_t i,const m98_css_stream *b,size_t j){
 const m98_css_token *x=m98_css_at(a,i),*y=m98_css_at(b,j);const uint32_t *u,*v;size_t k;
 if(!x||!y||x->value_length!=y->value_length)return 0;
 u=m98_css_value(a,x);v=m98_css_value(b,y);
 for(k=0;k<x->value_length;k++)if(u[k]!=v[k])return 0;
 return 1;
}
static int custom_name(const m98_css_stream *s){const m98_css_token *t=m98_css_at(s,0);const uint32_t *p;
 if(m98_css_count(s)!=1||!t||t->kind!=M98_CSS_IDENT||t->value_length<=2)return 0;
 p=m98_css_value(s,t);return p[0]=='-'&&p[1]=='-';}
static int find_token(const m98_css_snapshot *s,const m98_css_stream *name,size_t token){size_t i;
 for(i=0;i<s->n;i++)if(same(s->p[i].name,0,name,token))return (int)i;
 return -1;
}
static int find(const m98_css_snapshot *s,const m98_css_stream *name){return find_token(s,name,0);}
static int clone(const m98_css_allocator *a,const m98_css_stream *s,m98_css_stream **out){m98_css_stream *o=0;int r;size_t i;
 if((r=m98_css_empty(a,&o)))return r;
 for(i=0;i<m98_css_count(s);i++)if((r=m98_css_append(o,s,i))){m98_css_destroy(&o);return r;}
 *out=o;return 0;
}
static unsigned closer(unsigned kind){switch(kind){case M98_CSS_FUNCTION:case M98_CSS_LPAREN:return M98_CSS_RPAREN;case M98_CSS_LBRACKET:return M98_CSS_RBRACKET;case M98_CSS_LBRACE:return M98_CSS_RBRACE;default:return 0;}}
static int unsupported(const m98_css_stream *s,size_t i){
 const m98_css_token *t=m98_css_at(s,i);const uint32_t *v=m98_css_value(s,t);
 return (t->value_length>2&&v[0]=='-'&&v[1]=='-')||m98_css_ascii(s,i,"attr",1)||m98_css_ascii(s,i,"env",1)||m98_css_ascii(s,i,"if",1)||m98_css_ascii(s,i,"inherit",1)||m98_css_ascii(s,i,"first-valid",1)||m98_css_ascii(s,i,"random",1)||m98_css_ascii(s,i,"ident",1)||m98_css_ascii(s,i,"random-item",1);
}
static int argument_grammar(const m98_css_stream *,size_t,size_t,int);
static int normalize(m98_css_stream *s){unsigned stack[M98_CSS_DEPTH_MAX],substitution[M98_CSS_DEPTH_MAX];size_t depth=0,var_depth=0,i,j,comma,level,n=m98_css_count(s);int r,unsupported_found=0;
 for(i=0;i<n;i++){const m98_css_token *t=m98_css_at(s,i);unsigned c=closer(t->kind);
  if(t->kind==M98_CSS_BAD_STRING||t->kind==M98_CSS_BAD_URL)return M98_CSS_INVALID;
  if(t->kind==M98_CSS_FUNCTION&&unsupported(s,i))unsupported_found=1;
  if(var_depth&&t->kind==M98_CSS_FUNCTION&&m98_css_ascii(s,i,"var",1)&&i>=3){
   const m98_css_token *a=m98_css_at(s,i-3),*b=m98_css_at(s,i-2),*d=m98_css_at(s,i-1);
   if(a->kind==M98_CSS_DELIM&&b->kind==M98_CSS_DELIM&&d->kind==M98_CSS_DELIM&&a->delim=='.'&&b->delim=='.'&&d->delim=='.')unsupported_found=1;
  }
  if(c){if(depth==M98_CSS_DEPTH_MAX)return M98_CSS_LIMIT;stack[depth]=c;substitution[depth]=(unsigned)(t->kind==M98_CSS_FUNCTION&&m98_css_ascii(s,i,"var",1));var_depth+=substitution[depth++];}
  else if(t->kind==M98_CSS_RPAREN||t->kind==M98_CSS_RBRACKET||t->kind==M98_CSS_RBRACE){if(!depth||stack[depth-1]!=t->kind)return M98_CSS_INVALID;var_depth-=substitution[--depth];}
  else if(!depth&&(t->kind==M98_CSS_SEMICOLON||(t->kind==M98_CSS_DELIM&&t->delim=='!')))return M98_CSS_INVALID;
 }
 while(depth)if((r=m98_css_literal(s,stack[--depth],0)))return r;
 /* Custom-property specified grammar applies to every var(), including an
  * unused fallback. This pass performs no substitution and creates no dependency
  * edges: valid unused fallback cycles retain current short-circuit semantics. */
 n=m98_css_count(s);
 for(i=0;i<n;i++)if(m98_css_at(s,i)->kind==M98_CSS_FUNCTION&&m98_css_ascii(s,i,"var",1)){
  level=1;comma=n;
  for(j=i+1;j<n;j++){unsigned kind=m98_css_at(s,j)->kind;
   if(closer(kind))level++;
   else if(kind==M98_CSS_RPAREN||kind==M98_CSS_RBRACKET||kind==M98_CSS_RBRACE){if(!--level)break;}
   else if(kind==M98_CSS_COMMA&&level==1&&comma==n)comma=j;
  }
  if(j==n||!argument_grammar(s,i+1,comma==n?j:comma,1)||(comma!=n&&!argument_grammar(s,comma+1,j,0)))return M98_CSS_INVALID;
 }
 return unsupported_found?M98_CSS_UNSUPPORTED:0;
}
static size_t skip_ws(const m98_css_stream *s,size_t a,size_t b){while(a<b&&m98_css_at(s,a)->kind==M98_CSS_WS)a++;return a;}
static size_t trim_ws(const m98_css_stream *s,size_t a,size_t b){while(b>a&&m98_css_at(s,b-1)->kind==M98_CSS_WS)b--;return b;}
static int argument_grammar(const m98_css_stream *s,size_t a,size_t b,int required){
 size_t i,depth=0;if(required&&a==b)return 0;
 for(i=a;i<b;i++){const m98_css_token *t=m98_css_at(s,i);
  if(closer(t->kind))depth++;
  else if(t->kind==M98_CSS_RPAREN||t->kind==M98_CSS_RBRACKET||t->kind==M98_CSS_RBRACE)depth--;
  else if(!depth&&(t->kind==M98_CSS_SEMICOLON||(t->kind==M98_CSS_DELIM&&t->delim=='!')))return 0;
 }
 return 1;
}
static int keyword(const m98_css_stream *s,const char *text){size_t a=skip_ws(s,0,m98_css_count(s)),b=trim_ws(s,a,m98_css_count(s));return b==a+1&&m98_css_at(s,a)->kind==M98_CSS_IDENT&&m98_css_ascii(s,a,text,1);}
static int range(evaluator *,const m98_css_stream *,size_t,size_t,m98_css_stream *,unsigned,int *);
static int evaluate(evaluator *e,size_t index){property *p=e->s->p+index;m98_css_stream *result=0;size_t i;int r,invalid=0;
 if(p->state==2)return 0;
 if(p->state==1){for(i=0;i<e->depth;i++)if(e->stack[i]==index)break;for(;i<e->depth;i++)e->s->p[e->stack[i]].cycle=1;return 0;}
 if(e->depth>=M98_CSS_PROPERTY_MAX)return M98_CSS_LIMIT;
 p->state=1;e->stack[e->depth++]=index;
 r=m98_css_empty(&e->s->a,&result);
 if(!r)r=range(e,p->specified,0,m98_css_count(p->specified),result,0,&invalid);
 e->depth--;
 if(!r&&!invalid&&!p->cycle)r=normalize(result);
 if(!r&&!invalid&&!p->cycle){
  if(keyword(result,"revert")||keyword(result,"revert-layer")||keyword(result,"revert-rule"))r=M98_CSS_UNSUPPORTED;
  else if(keyword(result,"initial"))invalid=1;
  else if(keyword(result,"inherit")||keyword(result,"unset")){
   int inherited=e->parent?find(e->parent,p->name):-1;
   m98_css_destroy(&result);
   if(inherited<0||e->parent->p[inherited].invalid)invalid=1;
   else r=clone(&e->s->a,e->parent->p[inherited].computed,&result);
  }
 }
 if(r){p->state=0;m98_css_destroy(&result);return r;}
 p->invalid=(unsigned)(invalid||p->cycle);p->state=2;
 if(p->invalid)m98_css_destroy(&result);
 p->computed=result;return 0;
}
static int range(evaluator *e,const m98_css_stream *s,size_t a,size_t b,m98_css_stream *out,unsigned depth,int *invalid){
 size_t i=a,j,comma,level,k,x,y;int r,ix,bad; m98_css_stream *first=0,*ref=0;
 if(depth>M98_CSS_DEPTH_MAX)return M98_CSS_LIMIT;
 while(i<b){const m98_css_token *t=m98_css_at(s,i);
  if(t->kind!=M98_CSS_FUNCTION||!m98_css_ascii(s,i,"var",1)){if((r=m98_css_append(out,s,i++)))return r;continue;}
  /* Every function/block is balanced by normalize(). Find this closing paren
   * and the first top-level comma; all later commas belong to the fallback. */
  level=1;comma=b;j=i+1;
  for(;j<b;j++){unsigned kind=m98_css_at(s,j)->kind;
   if(closer(kind))level++;
   else if(kind==M98_CSS_RPAREN||kind==M98_CSS_RBRACKET||kind==M98_CSS_RBRACE){if(!--level)break;}
   else if(kind==M98_CSS_COMMA&&level==1&&comma==b)comma=j;
  }
  if(j==b)return M98_CSS_INVALID;
  /* Argument grammar is checked before replacement, including an unused
   * fallback. An invalid function does not evaluate its nested var() references,
   * but later active functions in this value still participate in cycles. */
  if(!argument_grammar(s,i+1,comma==b?j:comma,1)||
     (comma!=b&&!argument_grammar(s,comma+1,j,0))){*invalid=1;i=j+1;continue;}
  x=i+1;y=comma==b?j:comma;x=skip_ws(s,x,y);y=trim_ws(s,x,y);
  if((r=m98_css_empty(&e->s->a,&first)))return r;
  bad=0;r=range(e,s,x,y,first,depth+1,&bad);
  if(r){m98_css_destroy(&first);return r;}
  x=skip_ws(first,0,m98_css_count(first));y=trim_ws(first,x,m98_css_count(first));
  ix=-1;
  if(!bad&&y==x+1){const m98_css_token *key=m98_css_at(first,x);const uint32_t *v=m98_css_value(first,key);
   if(key->kind==M98_CSS_IDENT&&key->value_length>2&&v[0]=='-'&&v[1]=='-')ix=find_token(e->s,first,x);
  }
  m98_css_destroy(&first);
  bad=ix<0;
  if(ix>=0){property *p=e->s->p+(size_t)ix;
   if((r=evaluate(e,(size_t)ix)))return r;
   bad=p->invalid||p->cycle||p->state==1;ref=p->computed;
  }
  if(!bad){for(k=0;k<m98_css_count(ref);k++)if((r=m98_css_append(out,ref,k)))return r;}
  else if(comma!=b){bad=0;if((r=range(e,s,comma+1,j,out,depth+1,&bad)))return r;if(bad)*invalid=1;}
  else *invalid=1;
  i=j+1;
 }
 return 0;
}
void m98_css_snapshot_destroy(m98_css_snapshot **sp){m98_css_snapshot *s;size_t i;m98_css_allocator a;
 if(!sp||!*sp)return;
 s=*sp;*sp=0;a=s->a;
 for(i=0;i<s->n;i++){m98_css_destroy(&s->p[i].name);m98_css_destroy(&s->p[i].specified);m98_css_destroy(&s->p[i].computed);}
 a.free(a.user,s);
}
size_t m98_css_property_count(const m98_css_snapshot *s){return s?s->n:0;}
int m98_css_compute(const m98_css_declaration *d,size_t n,const m98_css_snapshot *parent,const m98_css_allocator *a,m98_css_snapshot **out){
 m98_css_snapshot *s=0;m98_css_stream *name=0,*value=0,*copy=0;size_t i,j;int r=0,ix,pi;unsigned wide;property *p;evaluator e;
 if(!out||(!d&&n)||!a||!a->alloc||!a->free)return M98_CSS_ARGUMENT;
 if(n>M98_CSS_PROPERTY_MAX)return M98_CSS_LIMIT;
 s=(m98_css_snapshot *)a->alloc(a->user,sizeof(*s));if(!s)return M98_CSS_MEMORY;
 memset(s,0,sizeof(*s));s->a=*a;
 if(parent)for(i=0;i<parent->n;i++){
  p=s->p+s->n++;if((r=clone(a,parent->p[i].name,&p->name)))goto fail;
  if(parent->p[i].computed&&(r=clone(a,parent->p[i].computed,&p->computed)))goto fail;
  p->invalid=parent->p[i].invalid;p->state=2;
 }
 for(i=0;i<n;i++){
  if((r=m98_css_tokenize(d[i].name,d[i].name_units,a,&name)))goto fail;
  if(!custom_name(name)){r=M98_CSS_ARGUMENT;goto fail;}
  ix=find(s,name);
  if(ix>=0&&s->p[ix].local){r=M98_CSS_ARGUMENT;goto fail;}
  if((r=m98_css_tokenize(d[i].value,d[i].value_units,a,&value))||(r=normalize(value)))goto fail;
  if(keyword(value,"revert")||keyword(value,"revert-layer")||keyword(value,"revert-rule")){r=M98_CSS_UNSUPPORTED;goto fail;}
  wide=keyword(value,"initial")?1:(keyword(value,"inherit")||keyword(value,"unset"))?2:0;
  if(ix<0){if(s->n==M98_CSS_PROPERTY_MAX){r=M98_CSS_LIMIT;goto fail;}ix=(int)s->n++;s->p[ix].name=name;name=0;}
  p=s->p+ix;p->local=1;m98_css_destroy(&name);m98_css_destroy(&p->computed);
  p->invalid=0;p->cycle=0;
  if(wide){
   pi=parent?find(parent,p->name):-1;p->state=2;
   if(wide==2&&pi>=0&&!parent->p[pi].invalid){if((r=clone(a,parent->p[pi].computed,&copy)))goto fail;p->computed=copy;copy=0;}
   else p->invalid=1;
   m98_css_destroy(&value);
  }else{p->specified=value;value=0;p->state=0;}
 }
 memset(&e,0,sizeof(e));e.s=s;e.parent=parent;
 for(j=0;j<s->n;j++)if((r=evaluate(&e,j)))goto fail;
 *out=s;return 0;
 fail:m98_css_destroy(&name);m98_css_destroy(&value);m98_css_destroy(&copy);m98_css_snapshot_destroy(&s);return r;
}
int m98_css_lookup(const m98_css_snapshot *s,const uint16_t *name,size_t n,const m98_css_stream **tokens,int *invalid){
 m98_css_stream *key=0;int r,ix;
 if(!s||!tokens||!invalid)return M98_CSS_ARGUMENT;
 if((r=m98_css_tokenize(name,n,&s->a,&key)))return r;
 if(!custom_name(key)){m98_css_destroy(&key);return M98_CSS_ARGUMENT;}
 ix=find(s,key);m98_css_destroy(&key);
 *tokens=ix<0?0:s->p[ix].computed;*invalid=ix<0?1:(int)s->p[ix].invalid;return 0;
}
int m98_css_substitute(const m98_css_snapshot *s,const uint16_t *text,size_t n,m98_css_stream **tokens,int *invalid){
 m98_css_stream *input=0,*output=0;evaluator e;int r,bad=0;
 if(!s||!tokens||!invalid)return M98_CSS_ARGUMENT;
 if((r=m98_css_tokenize(text,n,&s->a,&input))||(r=normalize(input)))goto fail;
 if((r=m98_css_empty(&s->a,&output)))goto fail;
 memset(&e,0,sizeof(e));e.s=(m98_css_snapshot *)s;
 r=range(&e,input,0,m98_css_count(input),output,0,&bad);
 if(r)goto fail;
 if(!bad&&(r=normalize(output)))goto fail;
 m98_css_destroy(&input);if(bad)m98_css_destroy(&output);*tokens=output;*invalid=bad;return 0;
 fail:m98_css_destroy(&input);m98_css_destroy(&output);return r;
}
