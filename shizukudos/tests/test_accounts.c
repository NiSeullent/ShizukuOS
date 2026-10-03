/* SPDX-License-Identifier: GPL-2.0-only */
#include "../accounts/account.h"
#include "../accounts/kdf.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int entropy(void *c, void *p, size_t n) {
    unsigned char *d=p; unsigned *v=c;
    while(n--) *d++=(unsigned char)++*v;
    return 0;
}
static int bad_entropy(void *c,void *p,size_t n) {(void)c;(void)p;(void)n;return -1;}
int main(void) {
    shz_accounts db; shz_subject guest={0},admin,user,other,sandbox; unsigned seed=0;
    unsigned char key[32];
    const unsigned char known[32]={0xae,0x4d,0x0c,0x95,0xaf,0x6b,0x46,0xd3,0x2d,0x0a,0xdf,0xf9,0x28,0xf0,0x6d,0xd0,0x2a,0x30,0x3f,0x8e,0xf3,0xc2,0x51,0xdf,0xd6,0xe2,0xd8,0x5a,0x95,0x47,0x4c,0x43};
    assert(!shz_pbkdf2("password",8,"salt",4,2,key));
    assert(!memcmp(key,known,32));
    assert(shz_pbkdf2("password",8,"salt",4,0,key));
    shz_accounts_init(&db,entropy,&seed);
    assert(shz_account_register(&db,&guest,0,"admin","correct horse",13,SHZ_ROLE_ADMIN)==SHZ_AUTH_DENIED);
    {
        shz_accounts before=db;
        unsigned entropy_before=seed;
        assert(shz_account_register(&db,&guest,1,"alice","alice pass",10,0)==SHZ_AUTH_DENIED);
        assert(!memcmp(&db,&before,sizeof db));
        assert(seed==entropy_before);
    }
    assert(!shz_account_register(&db,&guest,1,"admin","correct horse",13,SHZ_ROLE_ADMIN));
    assert(shz_account_register(&db,&guest,1,"evil","correct horse",13,SHZ_ROLE_ADMIN)==SHZ_AUTH_DENIED);
    assert(shz_account_login(&db,"admin","wrong wrong",11,1,&admin)==SHZ_AUTH_DENIED);
    assert(!shz_account_login(&db,"admin","correct horse",13,2,&admin));
    assert(admin.uid==1000&&admin.integrity==0x2000&&admin.roles==SHZ_ROLE_ADMIN);
    assert(shz_account_register(&db,&admin,0,"alice","alice pass",10,0)==SHZ_AUTH_DENIED);
    admin.integrity=0x3000;
    assert(!shz_account_register(&db,&admin,0,"alice","alice pass",10,0));
    assert(!shz_account_register(&db,&admin,0,"bob","bobby pass",10,0));
    assert(!shz_account_login(&db,"ALICE","alice pass",10,3,&user));
    assert(!shz_account_login(&db,"bob","bobby pass",10,4,&other));
    assert(!shz_subject_access(&user,&other));
    assert(!shz_subject_access(&guest,&user));
    assert(shz_subject_access(&admin,&user));
    sandbox=user;sandbox.integrity=0x1000;sandbox.roles=0;sandbox.flags=SHZ_SUBJECT_SANDBOX;
    assert(!shz_subject_access(&sandbox,&user));
    assert(shz_subject_access(&user,&sandbox));
    assert(shz_subject_path(&user,"C:\\Users\\1001\\notes.txt",1));
    assert(!shz_subject_path(&other,"C:\\Users\\1001\\notes.txt",0));
    assert(!shz_subject_path(&user,"C:\\Users\\1001\\..\\1002\\secret",0));
    assert(!shz_subject_path(&user,"C:\\Users\\10010\\secret",0));
    assert(!shz_subject_path(&user,"C:\\SHZ\\SYS64\\evil.dll",1));
    assert(!shz_subject_path(&user,"C:\\Users\\1001\\notes.txt:stream",1));
    assert(shz_subject_path(&user,"\\??\\C:\\SHZ\\SYS64\\ntdll.dll",0));
    assert(!shz_subject_path(&sandbox,"C:\\Users\\1001\\notes.txt",1));
    for(unsigned i=0;i<5;i++) assert(shz_account_login(&db,"alice","wrong wrong",11,10+i,&guest)==SHZ_AUTH_DENIED);
    assert(shz_account_login(&db,"alice","alice pass",10,15,&guest)==SHZ_AUTH_LOCKED);
    assert(!shz_account_login(&db,"alice","alice pass",10,30015,&guest));
    assert(guest.session!=user.session&&guest.auth_id!=user.auth_id);
    assert(!shz_subject_access(&guest,&user));
    assert(!shz_account_elevate(&db,"admin","correct horse",13,40000,&guest));
    assert(guest.integrity==0x3000&&guest.roles==SHZ_ROLE_ADMIN);
    assert(shz_account_elevate(&db,"bob","bobby pass",10,40000,&guest)==SHZ_AUTH_DENIED);
    shz_accounts_init(&db,bad_entropy,0);
    assert(shz_account_register(&db,&guest,1,"admin","correct horse",13,SHZ_ROLE_ADMIN)==SHZ_AUTH_ENTROPY);
    assert(!db.count);
    puts("accounts: KDF, enrollment, identities, elevation, throttle and path policy PASS");
}
