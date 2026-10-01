/* SPDX-License-Identifier: GPL-2.0-only
 * Real host sockets/kernel CSPRNG/UTC over the SAME controller and frozen
 * latest TLS backend. POSIX operations cannot prove the Win98 platform. */
#define _POSIX_C_SOURCE 200809L
#define M98_NET_IMPLEMENTATION
#include "m98_tls13_native.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static int owned=-1;
static uint32_t last_error;
static unsigned sends,recvs,waits;
static int start(m98_net_backend *api){
    if(owned!=-1)return M98_NET_STATE;
    *api=(m98_net_backend){m98_tls_create,m98_tls_handshake,m98_tls_write,m98_tls_read,m98_tls_shutdown,
        m98_tls_backend_error,m98_tls_verify_flags,m98_tls_is_established,m98_tls_free};return 0;
}
static int connect_tcp(const uint8_t *ip,uint16_t port){struct sockaddr_in a;int flags,result;
    owned=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(owned<0)goto bad;
    flags=fcntl(owned,F_GETFL,0);if(flags<0||fcntl(owned,F_SETFL,flags|O_NONBLOCK)<0)goto bad;
    memset(&a,0,sizeof(a));a.sin_family=AF_INET;a.sin_port=htons(port);memcpy(&a.sin_addr,ip,4);
    result=connect(owned,(const struct sockaddr *)&a,sizeof(a));
    if(!result)return 0;
    if(errno==EINPROGRESS)return M98_TLS_WANT_WRITE;
bad:last_error=(uint32_t)errno;return M98_NET_IO;
}
static int wait_socket(int want,uint32_t ms,int connecting){fd_set fd,errors;struct timeval t;int result;(void)connecting;
    FD_ZERO(&fd);FD_ZERO(&errors);FD_SET(owned,&fd);FD_SET(owned,&errors);
    t.tv_sec=ms/1000;t.tv_usec=(ms%1000)*1000;
    ++waits;result=select(owned+1,want==1?&fd:NULL,want==2?&fd:NULL,&errors,&t);
    if(result<0){last_error=(uint32_t)errno;return M98_NET_IO;}
    if(!result)return M98_NET_TIMEOUT;
    if(FD_ISSET(owned,&errors)||!FD_ISSET(owned,&fd))return M98_NET_IO;
    return 0;
}
static int finish(void){int error=0;socklen_t n=sizeof(error);
    if(getsockopt(owned,SOL_SOCKET,SO_ERROR,&error,&n)||n!=sizeof(error)||error){last_error=(uint32_t)(error?error:errno);return M98_NET_IO;}return 0;
}
static int half_close(void){if(shutdown(owned,SHUT_WR)){last_error=(uint32_t)errno;return M98_NET_IO;}return 0;}
static int send_data(void *u,const unsigned char *p,size_t n){ssize_t result;(void)u;++sends;if(n>17)n=17;
    result=send(owned,p,n,MSG_NOSIGNAL);if(result>=0)return (int)result;
    last_error=(uint32_t)errno;return errno==EAGAIN||errno==EWOULDBLOCK?-2:-1;
}
static int recv_data(void *u,unsigned char *p,size_t n){ssize_t result;(void)u;++recvs;if(n>13)n=13;
    result=recv(owned,p,n,0);if(result>=0)return (int)result;
    last_error=(uint32_t)errno;return errno==EAGAIN||errno==EWOULDBLOCK?-2:-1;
}
static int random_data(void *u,unsigned char *p,size_t n){ssize_t amount;(void)u;
    while(n){amount=getrandom(p,n,0);if(amount<0&&errno==EINTR)continue;if(amount<=0)return 0;p+=amount;n-=(size_t)amount;}return 1;
}
static int64_t utc(void *u){struct timespec t;(void)u;return clock_gettime(CLOCK_REALTIME,&t)?-1:(int64_t)t.tv_sec;}
static uint32_t tick(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))abort();return (uint32_t)((uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000);}
static uint32_t error(void){return last_error;}
static int stop(void){int result=0;if(owned!=-1){result=close(owned);owned=-1;}return result?M98_NET_CLEANUP:0;}
const m98_net_platform_ops m98_net_platform={start,connect_tcp,wait_socket,finish,half_close,send_data,recv_data,random_data,utc,tick,error,stop};
int main(int argc,char **argv){m98_net_options o={0};m98_net_details info={0};m98_net_handle h=0;
    unsigned char forward[3072],reverse[1021],expected[1021],*ca;size_t n,got=0,written=0;long length,port;
    FILE *file;int result,expect,passed=0;unsigned i;const char *mode;
    if(argc!=5)return 2;port=strtol(argv[1],NULL,10);if(port<1||port>65535)return 2;mode=argv[4];
    file=fopen(argv[2],"rb");if(!file)return 2;if(fseek(file,0,SEEK_END)||((length=ftell(file))<=0)||length>(1<<20)||fseek(file,0,SEEK_SET)){fclose(file);return 2;}
    ca=malloc((size_t)length+1);if(!ca){fclose(file);return 2;}if(fread(ca,1,(size_t)length,file)!=(size_t)length){fclose(file);free(ca);return 2;}fclose(file);ca[length]=0;
    o.size=sizeof(o);o.ipv4[0]=127;o.ipv4[3]=1;o.port=(uint16_t)port;o.hostname=argv[3];o.ca_pem=ca;o.ca_bytes=(uint32_t)length+1;
    o.connect_ms=1000;o.handshake_ms=!strcmp(mode,"handshake-timeout")?150:3000;o.io_ms=!strcmp(mode,"read-timeout")?150:3000;
    result=m98_net_open(&o,&h);
    expect=(!strcmp(mode,"wrong-host")||!strcmp(mode,"untrusted"))?M98_TLS_VERIFY:
           !strcmp(mode,"tls12")?M98_TLS_PROTOCOL:!strcmp(mode,"handshake-timeout")?M98_NET_TIMEOUT:
           !strcmp(mode,"connect-refused")?M98_NET_IO:0;
    if(expect){passed=result==expect&&!h&&owned==-1;goto done;}
    if(result)goto done;
    info.size=sizeof(info);if(m98_net_info(h,&info)||!info.established||info.verify_flags)goto done;
    for(i=0;i<sizeof(forward);++i)forward[i]=(unsigned char)(i*17u+3u);
    for(i=0;i<sizeof(expected);++i)expected[i]=(unsigned char)(i*31u+9u);
    if(m98_net_write(h,forward,sizeof(forward),&written)||written!=sizeof(forward))goto done;
    while(got<sizeof(reverse)){
        result=m98_net_read(h,reverse+got,sizeof(reverse)-got,&n);
        if(!strcmp(mode,"read-timeout")||!strcmp(mode,"truncated")){
            expect=!strcmp(mode,"read-timeout")?M98_NET_TIMEOUT:M98_TLS_PROTOCOL;
            passed=result==expect&&n==0&&got==0&&owned==-1;
            if(passed){info.size=sizeof(info);passed=m98_net_info(h,&info)==0&&!info.established&&info.result==expect;}
            goto done;
        }
        if(result||!n)goto done;got+=n;
    }
    passed=!memcmp(reverse,expected,sizeof(reverse))&&m98_net_shutdown(h)==0&&owned==-1&&sends>200&&recvs>60&&waits>1;
done:
    if(h&&m98_net_close(h))passed=0;
    if(owned!=-1)passed=0;
    memset(ca,0,(size_t)length+1);free(ca);
    printf("{\"passed\":%s,\"mode\":\"%s\",\"result\":%d,\"sends\":%u,\"receives\":%u,\"waits\":%u,\"written\":%zu,\"received\":%zu,\"native_windows\":false}\n",passed?"true":"false",mode,result,sends,recvs,waits,written,got);
    return passed?0:1;
}
