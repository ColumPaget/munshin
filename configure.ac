  
AC_INIT([main.c])

AC_PROG_CC
AC_LANG_C
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_HEADER_STDC
AC_SYS_LARGEFILE

AC_ARG_ENABLE(ssl, [  --enable-ssl              use Secure Sockets Layer (default=no)], cf_use_ssl=$enableval )
if test "$cf_use_ssl" = "yes"
then
AC_CHECK_LIB(ssl,SSL_library_init,,)
cf_have_libssl=$ac_cv_lib_ssl_SSL_library_init

AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_init
fi


AC_CHECK_LIB(crypt, crypt,,)
cf_have_libcrypt=$ac_cv_lib_crypt_crypt

AC_CHECK_HEADER(shadow.h,AC_DEFINE(HAVE_SHADOW_H, 1))


AC_ARG_WITH(system-libuseful, [  --with-system-libuseful       use systemwide libUseful.so rather than bundled version], cf_with_libuseful=$withval )

if test "$cf_with_libuseful" != "no" -a "$cf_with_libuseful" != ""
then
AC_CHECK_LIB([Useful],[OpenSSLVerifyCallback],
  [AC_CHECK_LIB([ssl],[SSL_new],,,[-lcrypto -lz])]
  [AC_CHECK_LIB([crypto],[ERR_load_CRYPTO_strings],,,[-lz])]
  [AC_CHECK_LIB([z],[inflate])]
  ,,[-lssl -lcrypto -lz])
AC_CHECK_LIB(Useful,GetToken)

LUSEFUL="system"
else
LUSEFUL="bundled"
STATIC_LIBS="libUseful/libUseful.a"
AC_SUBST(STATIC_LIBS)
AC_CONFIG_SUBDIRS([libUseful])
fi



dnl read Makefile.in and write Makefile 
AC_OUTPUT(Makefile)

