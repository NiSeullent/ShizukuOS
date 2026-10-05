#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Render the existing ShizukuOS Markdown guides as the official static portal.

Requires host-only Markdown==3.7. Writes only the explicit output directory.
The browser needs no package manager or server-side application.
"""
import argparse,html,json,re
from pathlib import Path
import markdown
PAGES=[('README','문서 안내'),('installation','설치와 첫 부팅'),('desktop','데스크톱과 파일'),
       ('security','계정과 보안'),('development','개발과 빌드'),('status','구현·검증 상태'),('interfaces','커널 인터페이스')]
CSS='''@import url("../fonts.css");
:root{color-scheme:light;--ink:#14292f;--muted:#536b74;--line:#dbe6e8;--accent:#086e74}
*{box-sizing:border-box}body{margin:0;font-family:"Pretendard Variable","Noto Sans KR",sans-serif;background:#f4f8f9;color:var(--ink);line-height:1.8}a{color:var(--accent);text-underline-offset:3px}header{background:#fff;border-bottom:1px solid var(--line);padding:18px max(24px,calc((100vw - 1200px)/2));display:flex;align-items:center;gap:32px}header>a:first-child{font-weight:800;font-size:22px;text-decoration:none}header nav{display:flex;gap:22px;flex-wrap:wrap;font-size:14px}header nav a{text-decoration:none}.layout{display:grid;grid-template-columns:240px minmax(0,840px);gap:40px;max-width:1200px;margin:40px auto;padding:0 24px}aside{position:sticky;top:24px;align-self:start}aside strong{display:block;margin:8px 12px 16px;font-size:12px;color:var(--muted)}aside a{display:block;text-decoration:none;padding:10px 12px;margin:3px 0;border-radius:8px;color:var(--muted)}aside a[aria-current=page]{background:#e0f0ed;color:#06575b;font-weight:700}main{min-width:0;background:white;padding:36px 44px;border:1px solid var(--line);border-radius:18px;box-shadow:0 8px 32px #19353608}h1{font-size:32px;line-height:1.3;letter-spacing:-.7px;margin:0 0 26px}h2{font-size:23px;line-height:1.5;margin-top:36px;padding-top:10px}p,li{font-size:15px}table{display:block;width:100%;overflow:auto;border-collapse:collapse;font-size:14px;margin:24px 0}th,td{padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left;min-width:130px}th{background:#f1f6f7}code{font-family:ui-monospace,monospace;font-size:.9em;overflow-wrap:anywhere;background:#edf4f5;padding:2px 5px;border-radius:4px}pre{overflow:auto;background:#edf4f5;padding:18px;border-radius:9px}pre code{padding:0;white-space:pre}footer{max-width:1200px;margin:36px auto;padding:0 24px 30px;font-size:13px;color:var(--muted)}input{font:inherit;width:100%;padding:9px 12px;border:1px solid #b7cccf;border-radius:8px;background:white}#results{margin:6px 0 18px}#results a{border:1px solid var(--line);background:white;font-size:13px}label{font-size:13px;font-weight:700;display:block;margin:12px 0 6px}.skip{position:absolute;top:-60px}.skip:focus{top:5px;background:white;padding:8px;z-index:5}@media(max-width:800px){header{gap:14px;padding:16px 20px;flex-wrap:wrap}.layout{grid-template-columns:1fr;gap:22px;margin:24px auto;padding:0 16px}aside{position:static}aside nav{display:flex;flex-wrap:wrap;gap:2px}aside nav a{font-size:13px;padding:6px 10px}aside strong{margin-left:0}main{padding:25px 22px;border-radius:12px}h1{font-size:27px}}
'''
JS='''const input=document.getElementById('doc-search'),results=document.getElementById('results');let pages=[];
fetch('./search.json').then(r=>{if(!r.ok)throw Error();return r.json()}).then(p=>pages=p).catch(()=>{input.placeholder='아래 문서 목록을 이용하세요';input.disabled=true});
input.addEventListener('input',()=>{results.replaceChildren();const q=input.value.trim().toLocaleLowerCase();if(!q)return;const found=pages.filter(p=>(p.title+' '+p.text).toLocaleLowerCase().includes(q)).slice(0,7);for(const p of found){const a=document.createElement('a');a.href=p.href;a.textContent=p.title;results.append(a)}if(!found.length){const p=document.createElement('p');p.textContent='일치하는 문서가 없습니다.';results.append(p)}});
'''
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1]/'docs/shizukuos');parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=True);search=[]
    for slug,title in PAGES:
        text=(args.source/(slug+'.md')).read_text();body=markdown.markdown(text,extensions=['tables','fenced_code'])
        for key,label in PAGES:body=body.replace('href="'+key+'.md"','href="'+('index' if key=='README' else key)+'.html"')
        nav=''.join('<a href="'+('index' if key=='README' else key)+'.html"'+(' aria-current="page"' if key==slug else '')+'>'+html.escape(label)+'</a>' for key,label in PAGES)
        filename=('index' if slug=='README' else slug)+'.html'
        rendered='<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+html.escape(title)+' · ShizukuOS 문서</title><meta name="description" content="ShizukuOS 설치·계정·데스크톱·파일·개발 문서와 실제 검증 상태"><link rel="stylesheet" href="./docs.css"><link rel="icon" href="../favicon.svg"><script src="./search.js" defer></script></head><body><a class="skip" href="#main">본문으로</a><header><a href="../index.html">ShizukuOS</a><nav aria-label="공식 사이트"><a href="../downloads.html">다운로드</a><a href="./index.html">문서</a><a href="https://github.com/NiSeullent/ShizukuOS">GitHub</a></nav></header><div class="layout"><aside><strong>SHIZUKUOS 안내</strong><label for="doc-search">문서 검색</label><input id="doc-search" type="search" placeholder="설치, 계정, 파일…" autocomplete="off"><div id="results" aria-live="polite"></div><nav aria-label="문서 목록">'+nav+'</nav></aside><main id="main">'+body+'</main></div><footer>ShizukuOS · Pre-Beta 01 통합 중 · 2026-10-05 기준<br><a href="https://github.com/NiSeullent/ShizukuOS/tree/main/docs/shizukuos">문서 원본과 수정 이력</a></footer></body></html>'
        (args.out/filename).write_text(rendered+'\n');search.append({'title':title,'href':'./'+filename,'text':re.sub(r'[`#*]','',text)})
    (args.out/'docs.css').write_text(CSS);(args.out/'search.js').write_text(JS);(args.out/'search.json').write_text(json.dumps(search,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'pages':len(PAGES),'output':str(args.out)}))
if __name__=='__main__':main()
