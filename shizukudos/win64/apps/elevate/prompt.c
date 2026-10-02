/* SPDX-License-Identifier: GPL-2.0-only
 * Own credential entry: plaintext never enters a window title or EDIT control.
 * This is a masked prompt, not a qualified secure desktop.
 */
#include "prompt.h"
#include "secret.h"
static shz_secret secret;
static int result,done;
static unsigned char *destination;static unsigned capacity;
static WCHAR account_label[300],command_label[300];
static void accept_password(HWND w) {
 int n;if(secret.length<8)return;
 n=WideCharToMultiByte(CP_UTF8,0,(const WCHAR *)secret.chars,(int)secret.length,(char *)destination,(int)capacity,0,0);
 shz_secret_reset(&secret);
 if(n<8||n>(int)capacity){SecureZeroMemory(destination,capacity);InvalidateRect(w,0,TRUE);return;}
 result=n;done=1;DestroyWindow(w);
}
static LRESULT CALLBACK proc(HWND w,UINT m,WPARAM wp,LPARAM lp) {
 if(m==WM_CHAR){if(wp==13){accept_password(w);return 0;}if(wp==27){done=1;shz_secret_reset(&secret);DestroyWindow(w);return 0;}if(shz_secret_key(&secret,(uint16_t)wp))InvalidateRect(w,0,FALSE);return 0;}
 if(m==WM_LBUTTONUP){int x=(short)LOWORD(lp),y=(short)HIWORD(lp);if(y>=120&&y<148){if(x>=280&&x<380)accept_password(w);else if(x>=392&&x<492){done=1;shz_secret_reset(&secret);DestroyWindow(w);}}return 0;}
 if(m==WM_PAINT){PAINTSTRUCT ps;HDC dc=BeginPaint(w,&ps);WCHAR mask[129];RECT r;
  if(!dc)return 0;
  SetBkMode(dc,TRANSPARENT);
  r=(RECT){12,10,492,32};DrawTextW(dc,account_label,-1,&r,DT_LEFT|DT_SINGLELINE);
  r=(RECT){12,36,492,74};DrawTextW(dc,command_label,-1,&r,DT_LEFT|DT_WORDBREAK);
  Rectangle(dc,12,80,492,108);shz_secret_mask(&secret,(uint16_t *)mask);r=(RECT){18,84,486,104};DrawTextW(dc,mask,-1,&r,DT_LEFT|DT_SINGLELINE);SecureZeroMemory(mask,sizeof mask);
  Rectangle(dc,280,120,380,148);r=(RECT){280,120,380,148};DrawTextW(dc,L"Authenticate",-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
  Rectangle(dc,392,120,492,148);r=(RECT){392,120,492,148};DrawTextW(dc,L"Cancel",-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
  EndPaint(w,&ps);return 0;
 }
 if(m==WM_GETTEXT||m==WM_GETTEXTLENGTH||m==WM_COPY||m==WM_CUT||m==WM_PASTE)return 0;
 if(m==WM_CLOSE){shz_secret_reset(&secret);done=1;DestroyWindow(w);return 0;}
 return DefWindowProcW(w,m,wp,lp);
}
int shz_password_prompt(const char *user,const char *command,unsigned char *out,unsigned cap) {
 WNDCLASSW cls={0};HWND w;MSG msg;
 result=done=0;destination=out;capacity=cap;SecureZeroMemory(out,cap);shz_secret_reset(&secret);
 if(!MultiByteToWideChar(CP_UTF8,0,user,-1,account_label,300)||!MultiByteToWideChar(CP_UTF8,0,command,-1,command_label,300))return 0;
 cls.lpfnWndProc=proc;cls.hInstance=GetModuleHandleW(0);cls.lpszClassName=L"SHZ_AUTH_PROMPT";cls.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);cls.hCursor=LoadCursorW(0,MAKEINTRESOURCEW(32512));
 if(!RegisterClassW(&cls)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return 0;
 w=CreateWindowExW(WS_EX_TOPMOST,cls.lpszClassName,L"Shizuku account authentication",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,100,100,520,220,0,0,cls.hInstance,0);
 if(!w)return 0;
 ShowWindow(w,SW_SHOW);SetFocus(w);
 while(!done&&GetMessageW(&msg,0,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
 shz_secret_reset(&secret);
 if(!done){DestroyWindow(w);SecureZeroMemory(out,cap);return 0;}return result;
}
