/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_css_test_support.h"
#include "css_selected_vectors.h"
static m98_css_snapshot *compute(heap *h,const char *const *names,const char *const *values,size_t n,const m98_css_snapshot *parent){m98_css_declaration d[64];uint16_t ns[64][128],vs[64][512];size_t i;m98_css_snapshot *s=0;m98_css_allocator a=allocator(h);
 CHECK(n<=64);for(i=0;i<n;i++){d[i].name=ns[i];d[i].name_units=utf16(names[i],ns[i]);d[i].value=vs[i];d[i].value_units=utf16(values[i],vs[i]);}CHECK(m98_css_compute(d,n,parent,&a,&s)==0);return s;
}
static void value(heap *h,const m98_css_snapshot *s,const char *name,const char *text){uint16_t key[128];const m98_css_stream *o=(const m98_css_stream *)(uintptr_t)1;int invalid=123;size_t n=utf16(name,key);
 CHECK(m98_css_lookup(s,key,n,&o,&invalid)==0);CHECK(invalid==(text==0));if(text)expected(h,o,text);else CHECK(o==0);
}
static void substitution(heap *h,const m98_css_snapshot *s,const char *input,const char *text){uint16_t p[512];m98_css_stream *o=0;int bad=123;size_t n=utf16(input,p);
 CHECK(m98_css_substitute(s,p,n,&o,&bad)==0);CHECK(bad==(text==0));if(text)expected(h,o,text);else CHECK(o==0);m98_css_destroy(&o);
}
static void source_error(const m98_css_snapshot *s,const char *input,int error){uint16_t p[512];m98_css_stream *o=(m98_css_stream *)(uintptr_t)1;int bad=123;size_t n=utf16(input,p);
 CHECK(m98_css_substitute(s,p,n,&o,&bad)==error);CHECK(o==(m98_css_stream *)(uintptr_t)1&&bad==123);
}
static void vectors(heap *h){size_t i,j,rotation;for(i=0;i<sizeof(variable_vectors)/sizeof(variable_vectors[0]);i++){const css_variable_vector *v=variable_vectors+i;
  for(rotation=0;rotation<v->count;rotation++){const char *names[64],*values[64];m98_css_snapshot *s;
   for(j=0;j<v->count;j++){names[j]=v->names[(j+rotation)%v->count];values[j]=v->values[(j+rotation)%v->count];}
   s=compute(h,names,values,v->count,0);
   for(j=0;j<v->count;j++)value(h,s,v->names[j],v->expected[j]);m98_css_snapshot_destroy(&s);
  }
 }}
static void current_cycles(heap *h){const char *names[]={"--a","--b","--c","--good","--x","--y","--t","--u"};const char *values[]={"var(--a,blue)","var(--a,green)","var(--a,blue)","1px","var(--good,var(--y))","var(--good,var(--x))","var(--missing,var(--u))","var(--missing,var(--t))"};m98_css_snapshot *s=compute(h,names,values,8,0);
 value(h,s,"--a",0);value(h,s,"--b","green");value(h,s,"--c","blue");value(h,s,"--x","1px");value(h,s,"--y","1px");value(h,s,"--t",0);value(h,s,"--u",0);m98_css_snapshot_destroy(&s);
}
static void inheritance(heap *h){const char *names[]={"--base","--alias","--invalid","--kw","--empty"};const char *values[]={"red","var(--base)","initial","unset",""};const char *cn[]={"--base","--alias2","--invalid","--kw"};const char *cv[]={"blue","var(--alias)","inherit","inherit"};m98_css_snapshot *parent=compute(h,names,values,5,0),*child=compute(h,cn,cv,4,parent),*other=compute(h,0,0,0,parent);
 m98_css_snapshot_destroy(&parent);value(h,child,"--base","blue");value(h,child,"--alias","red");value(h,child,"--alias2","red");value(h,child,"--invalid",0);value(h,child,"--kw",0);value(h,child,"--empty","");value(h,other,"--base","red");
 substitution(h,child,"var(--empty,fallback)","");substitution(h,child,"var(--missing,)","");substitution(h,child,"var(--missing)",0);substitution(h,child,"var(--invalid,var(--base))","blue");substitution(h,child,"'var(--base)'", "'var(--base)'");substitution(h,child,"url(var--base)","url(var--base)");substitution(h,child,"var(--missing, ) var(--missing, )", "   ");
 m98_css_snapshot_destroy(&child);value(h,other,"--alias","red");m98_css_snapshot_destroy(&other);m98_css_snapshot_destroy(&other);
}
static void names_adjacency(heap *h){const char *names[]={"--A","--a","--name","--wide","--value","--num","--unit"};const char *values[]={"green","red"," --a ","initial","var(--missing,initial)","1","em"};m98_css_snapshot *s=compute(h,names,values,7,0);
 substitution(h,s,"var(--A)","green");substitution(h,s,"var(var(--name))","red");substitution(h,s,"var(foo,green)","green");source_error(s,"var(,green)",M98_CSS_INVALID);source_error(s,"var(/*only comment*/,green)",M98_CSS_INVALID);source_error(s,"var(--A,red;blue)",M98_CSS_INVALID);source_error(s,"var(--A,red!blue)",M98_CSS_INVALID);source_error(s,"var(--missing!x,green)",M98_CSS_INVALID);source_error(s,"var(--missing;x,green)",M98_CSS_INVALID);source_error(s,"var(--A,var())",M98_CSS_INVALID);source_error(s,"var(--A,foo(var()))",M98_CSS_INVALID);substitution(h,s,"var(--missing,foo(!;))","foo(!;)");value(h,s,"--wide",0);value(h,s,"--value",0);
 substitution(h,s,"var( ,green)","green");substitution(h,s,"var(--missing,initial)","initial");substitution(h,s,"...var(--a)","...red");substitution(h,s,". . .var(--a)",". . .red");substitution(h,s,"var(... var(--name),green)","green");substitution(h,s,"var(. . .var(--name),green)","green");substitution(h,s,"...red","...red");
 substitution(h,s,"var(--num)var(--unit)","1/**/em");substitution(h,s,"var(--num)var(--missing,)var(--unit)","1/**/em");substitution(h,s,"rgb(var(--num),0,0)","rgb(1,0,0)");substitution(h,s,"var(--missing,red,blue)","red,blue");substitution(h,s,"var(--missing,var(--a)","red");
 m98_css_snapshot_destroy(&s);
 {uint16_t n1[]={'-','-',0xf3},n2[]={'-','-','o',0x301},v1[]={'a'},v2[]={'b'};m98_css_declaration d[]={{n1,v1,3,1},{n2,v2,4,1}};m98_css_allocator a=allocator(h);const m98_css_stream *o;int bad;
 CHECK(m98_css_compute(d,2,0,&a,&s)==0);CHECK(m98_css_lookup(s,n1,3,&o,&bad)==0&&!bad);expected(h,o,"a");CHECK(m98_css_lookup(s,n2,4,&o,&bad)==0&&!bad);expected(h,o,"b");m98_css_snapshot_destroy(&s);}
}
static int one(heap *h,const char *name,const char *value,m98_css_snapshot **s){uint16_t n[128],v[512];m98_css_declaration d;m98_css_allocator a=allocator(h);d.name=n;d.name_units=utf16(name,n);d.value=v;d.value_units=utf16(value,v);return m98_css_compute(&d,1,0,&a,s);}
static void specified_var_grammar(heap *h){const char *bad[]={"var()","var(,green)","var(/*comment*/,green)","var(--a,var())","var(--a,foo(var()))","var(--a,var(,var(--x)))","var(--a,red;blue)","var(--a,red!blue)","var(--x!bad,green)"};size_t i;m98_css_snapshot *sentinel=(m98_css_snapshot *)(uintptr_t)1,*parent=0;const char *names[]={"--a"},*values[]={"red"};
 parent=compute(h,names,values,1,0);
 for(i=0;i<sizeof(bad)/sizeof(bad[0]);i++){uint16_t name[]={'-','-','b'},text[512];m98_css_declaration d;m98_css_allocator a=allocator(h);size_t live=h->live;d.name=name;d.name_units=3;d.value=text;d.value_units=utf16(bad[i],text);
  CHECK(m98_css_compute(&d,1,parent,&a,&sentinel)==M98_CSS_INVALID);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);CHECK(h->live==live);value(h,parent,"--a","red");
 }
 m98_css_snapshot_destroy(&parent);CHECK(h->live==0);
}
static void computed_keywords(heap *h){const char *names[]={"--a","--b","--c","--self"},*pv[]={"red","green","black","purple"},*cv[]={"var(--missing,InHeRiT)","var(--missing,unset)","var(--missing,initial)","var(--self,inherit)"};m98_css_snapshot *parent=compute(h,names,pv,4,0),*child=compute(h,names,cv,4,parent),*sentinel=(m98_css_snapshot *)(uintptr_t)1;
 m98_css_snapshot_destroy(&parent);value(h,child,"--a","red");value(h,child,"--b","green");value(h,child,"--c",0);value(h,child,"--self",0);m98_css_snapshot_destroy(&child);
 CHECK(one(h,"--a","var(--missing,revert)",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--a","var(--missing,revert-layer)",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--a","var(--missing,revert-rule)",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--a","revert-rule",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);CHECK(h->live==0);
}
static void composed_depth(heap *h){uint16_t name[]={'-','-','a'},deep[129],wrap[32];m98_css_declaration d;m98_css_allocator a=allocator(h);m98_css_snapshot *parent=0,*sentinel=(m98_css_snapshot *)(uintptr_t)1;m98_css_stream *output=(m98_css_stream *)(uintptr_t)1;int bad=123;size_t i;
 for(i=0;i<64;i++){deep[i]='(';deep[128-i]=')';}deep[64]='x';d.name=name;d.name_units=3;d.value=deep;d.value_units=129;CHECK(m98_css_compute(&d,1,0,&a,&parent)==0);
 d.name_units=utf16("--b",name);d.value=wrap;d.value_units=utf16("(var(--a))",wrap);CHECK(m98_css_compute(&d,1,parent,&a,&sentinel)==M98_CSS_LIMIT);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);
 CHECK(m98_css_substitute(parent,wrap,d.value_units,&output,&bad)==M98_CSS_LIMIT);CHECK(output==(m98_css_stream *)(uintptr_t)1&&bad==123);
 {const m98_css_stream *still=0;uint16_t key[]={'-','-','a'};CHECK(m98_css_lookup(parent,key,3,&still,&bad)==0&&!bad);CHECK(m98_css_count(still)==129);roundtrip(h,still);}
 m98_css_snapshot_destroy(&parent);CHECK(h->live==0);
}
static void expansion_limits(heap *h){m98_css_allocator a=allocator(h);uint16_t key1[]={'-','-','a'},key2[]={'-','-','b'},refs[128];uint16_t *large=(uint16_t *)malloc(30000*sizeof(*large));m98_css_snapshot *sentinel=(m98_css_snapshot *)(uintptr_t)1;size_t i;m98_css_declaration d[2];
 CHECK(large!=0);for(i=0;i<30000;i++)large[i]='x';d[0].name=key1;d[0].name_units=3;d[0].value=large;d[0].value_units=30000;d[1].name=key2;d[1].name_units=3;d[1].value=refs;d[1].value_units=utf16("var(--a)var(--a)var(--a)var(--a)var(--a)",refs);
 CHECK(m98_css_compute(d,2,0,&a,&sentinel)==M98_CSS_LIMIT);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);CHECK(h->live==0);
 for(i=0;i<4000;i++)large[i]=i%2?' ':'x';d[0].value_units=4000;d[1].value_units=utf16("var(--a)var(--a)",refs);CHECK(m98_css_compute(d,2,0,&a,&sentinel)==M98_CSS_LIMIT);CHECK(h->live==0);free(large);
 {uint16_t names[64][8],v[]={'x'},newkey[]={'-','-','z','z'};m98_css_declaration many[64];m98_css_snapshot *parent=0;
 for(i=0;i<64;i++){names[i][0]='-';names[i][1]='-';names[i][2]='a'+(uint16_t)(i/26);names[i][3]='a'+(uint16_t)(i%26);many[i].name=names[i];many[i].name_units=4;many[i].value=v;many[i].value_units=1;}
 CHECK(m98_css_compute(many,64,0,&a,&parent)==0);CHECK(m98_css_property_count(parent)==64);d[0].name=newkey;d[0].name_units=4;d[0].value=v;d[0].value_units=1;CHECK(m98_css_compute(d,1,parent,&a,&sentinel)==M98_CSS_LIMIT);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);m98_css_snapshot_destroy(&parent);CHECK(h->live==0);}
}
static void invalid_bounds_faults(heap *h){const char *names[]={"--a","--b","--c","--d"};const char *values[]={"1px","var(--a)","var(--missing,var(--b))","calc(var(--c) + 1px)"};m98_css_snapshot *s=0,*parent=compute(h,names,values,4,0),*sentinel=(m98_css_snapshot *)(uintptr_t)1;size_t base,count,i;uint16_t n[]={'-','-','x'},deep[140];m98_css_declaration d={n,deep,3,140};m98_css_allocator a=allocator(h);
 CHECK(one(h,"--","red",&sentinel)==M98_CSS_ARGUMENT);CHECK(one(h,"x","red",&sentinel)==M98_CSS_ARGUMENT);CHECK(one(h,"--x","revert",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","revert-layer",&sentinel)==M98_CSS_UNSUPPORTED);
 CHECK(one(h,"--x","attr(title)",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","env(foo)",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","if(foo)",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","ident(var(--x))",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","random-item(red,var(--x))",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","--custom(var(--x))",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","var(--a,IDENT(var(--x)))",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","var(...var(--name),green)",&sentinel)==M98_CSS_UNSUPPORTED);CHECK(one(h,"--x","x;y",&sentinel)==M98_CSS_INVALID);CHECK(one(h,"--x","x!important",&sentinel)==M98_CSS_INVALID);CHECK(one(h,"--x", "x)",&sentinel)==M98_CSS_INVALID);CHECK(one(h,"--x","'x\ny'",&sentinel)==M98_CSS_INVALID);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);
 for(i=0;i<70;i++){deep[i]='(';deep[139-i]=')';}CHECK(m98_css_compute(&d,1,0,&a,&sentinel)==M98_CSS_LIMIT);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);
 {const char *dn[]={"--x","--x"},*dv[]={"red","blue"};uint16_t ns[2][8],vs[2][8];m98_css_declaration dd[2];for(i=0;i<2;i++){dd[i].name=ns[i];dd[i].name_units=utf16(dn[i],ns[i]);dd[i].value=vs[i];dd[i].value_units=utf16(dv[i],vs[i]);}CHECK(m98_css_compute(dd,2,0,&a,&sentinel)==M98_CSS_ARGUMENT);}
 base=h->calls;s=compute(h,names,values,4,parent);count=h->calls-base;m98_css_snapshot_destroy(&s);
 for(i=1;i<=count;i++){uint16_t ns[4][32],vs[4][128];m98_css_declaration dd[4];size_t j,live=h->live;for(j=0;j<4;j++){dd[j].name=ns[j];dd[j].name_units=utf16(names[j],ns[j]);dd[j].value=vs[j];dd[j].value_units=utf16(values[j],vs[j]);}h->fail=h->calls+i;CHECK(m98_css_compute(dd,4,parent,&a,&sentinel)==M98_CSS_MEMORY);CHECK(sentinel==(m98_css_snapshot *)(uintptr_t)1);CHECK(h->live==live);h->fail=0;value(h,parent,"--a","1px");}
 m98_css_snapshot_destroy(&parent);CHECK(h->live==0);
}
int main(void){heap h={0};vectors(&h);current_cycles(&h);inheritance(&h);names_adjacency(&h);specified_var_grammar(&h);computed_keywords(&h);composed_depth(&h);expansion_limits(&h);invalid_bounds_faults(&h);CHECK(h.live==0);printf("PASS CSS variables current active-fallback: %u assertions; no native/style/paint claim\n",checks);return 0;}
