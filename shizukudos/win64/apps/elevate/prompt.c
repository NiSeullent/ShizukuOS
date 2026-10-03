/* SPDX-License-Identifier: GPL-2.0-only
 * Own credential entry: plaintext never enters a window title or EDIT control.
 * This is a masked prompt, not a qualified secure desktop.
 */
#include "prompt.h"
#include "secret.h"
static shz_secret secret;
static int result,done,consent_shown;
static unsigned char *destination;static unsigned capacity;
static WCHAR account_label[300],command_label[1024];
static void accept_password(HWND w) {
 int n;if(!consent_shown||secret.length<8)return;
 n=WideCharToMultiByte(CP_UTF8,0,(const WCHAR *)secret.chars,(int)secret.length,(char *)destination,(int)capacity,0,0);
 shz_secret_reset(&secret);
 if(n<8||n>(int)capacity){SecureZeroMemory(destination,capacity);InvalidateRect(w,0,TRUE);return;}
 result=n;done=1;DestroyWindow(w);
}
static LRESULT CALLBACK proc(HWND w,UINT m,WPARAM wp,LPARAM lp) {
 if(m==WM_CHAR){if(wp==13){accept_password(w);return 0;}if(wp==27){done=1;shz_secret_reset(&secret);DestroyWindow(w);return 0;}if(shz_secret_key(&secret,(uint16_t)wp))InvalidateRect(w,0,FALSE);return 0;}
 if(m==WM_LBUTTONUP){int x=(short)LOWORD(lp),y=(short)HIWORD(lp);if(y>=368&&y<396){if(x>=400&&x<500)accept_password(w);else if(x>=512&&x<612){done=1;shz_secret_reset(&secret);DestroyWindow(w);}}return 0;}
 if(m==WM_SIZE){consent_shown=0;InvalidateRect(w,0,TRUE);return 0;}
 if(m==WM_PAINT){PAINTSTRUCT ps;HDC dc=BeginPaint(w,&ps);WCHAR mask[129];RECT r,client,measured;int height;
  consent_shown=0;
  if(!dc)return 0;
  SetBkMode(dc,TRANSPARENT);
  if(!GetClientRect(w,&client)||client.right<624||client.bottom<396)goto unreadable;
  r=(RECT){12,10,612,32};measured=r;
  height=DrawTextW(dc,account_label,-1,&measured,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX|DT_CALCRECT);
  if(height<=0||measured.right>r.right||measured.bottom>r.bottom||
     DrawTextW(dc,account_label,-1,&r,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX)!=height)goto unreadable;
  r=(RECT){12,36,612,308};measured=r;
  height=DrawTextW(dc,command_label,-1,&measured,DT_LEFT|DT_WORDBREAK|DT_NOPREFIX|DT_CALCRECT);
  if(height<=0||measured.right>r.right||measured.bottom>r.bottom||
     DrawTextW(dc,command_label,-1,&r,DT_LEFT|DT_WORDBREAK|DT_NOPREFIX)!=height)goto unreadable;
  consent_shown=1;
  Rectangle(dc,12,324,612,352);shz_secret_mask(&secret,(uint16_t *)mask);r=(RECT){18,328,606,348};DrawTextW(dc,mask,-1,&r,DT_LEFT|DT_SINGLELINE);SecureZeroMemory(mask,sizeof mask);
  Rectangle(dc,400,368,500,396);r=(RECT){400,368,500,396};DrawTextW(dc,L"Authenticate",-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
  Rectangle(dc,512,368,612,396);r=(RECT){512,368,612,396};DrawTextW(dc,L"Cancel",-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
  EndPaint(w,&ps);return 0;
unreadable:
  EndPaint(w,&ps);shz_secret_reset(&secret);SecureZeroMemory(destination,capacity);done=1;DestroyWindow(w);return 0;
 }
 if(m==WM_GETTEXT||m==WM_GETTEXTLENGTH||m==WM_COPY||m==WM_CUT||m==WM_PASTE)return 0;
 if(m==WM_CLOSE){shz_secret_reset(&secret);done=1;DestroyWindow(w);return 0;}
 return DefWindowProcW(w,m,wp,lp);
}
int shz_password_prompt(const char *user,const char *command,unsigned char *out,unsigned cap) {
 WNDCLASSW cls={0};HWND w;MSG msg;
 int accepted=0;
 if(!out||!cap)return 0;
 result=done=consent_shown=0;destination=out;capacity=cap;SecureZeroMemory(out,cap);shz_secret_reset(&secret);
 if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,user,-1,account_label,300)||!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,command,-1,command_label,1024))goto cleanup;
 cls.lpfnWndProc=proc;cls.hInstance=GetModuleHandleW(0);cls.lpszClassName=L"SHZ_AUTH_PROMPT";cls.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);cls.hCursor=LoadCursorW(0,MAKEINTRESOURCEW(32512));
 if(!RegisterClassW(&cls)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)goto cleanup;
 w=CreateWindowExW(WS_EX_TOPMOST,cls.lpszClassName,L"Shizuku account authentication",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,0,0,640,440,0,0,cls.hInstance,0);
 if(!w)goto cleanup;
 ShowWindow(w,SW_SHOW);SetFocus(w);
 while(!done&&GetMessageW(&msg,0,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
 shz_secret_reset(&secret);
 if(!done){DestroyWindow(w);SecureZeroMemory(out,cap);}else accepted=result;
cleanup:
 shz_secret_reset(&secret);SecureZeroMemory(account_label,sizeof account_label);SecureZeroMemory(command_label,sizeof command_label);
 destination=0;capacity=0;consent_shown=0;return accepted;
}
