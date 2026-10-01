# ShizukuDOS "Shizuku" port (overlay, shizukudos/win64/webkit/port): PAL as for the Windows port (OpenSSL digests,
# generic clock, Win32 system beep).
list(APPEND PAL_SOURCES
    crypto/openssl/CryptoDigestOpenSSL.cpp

    system/ClockGeneric.cpp

    system/win/SoundWin.cpp

    text/KillRing.cpp
)

list(APPEND PAL_PRIVATE_LIBRARIES
    OpenSSL::Crypto
)
