AC_PREREQ([2.63])
AC_INIT([fs-hasher], [0.9.4], [fsltraces@fsl.cs.sunysb.edu])
AC_LANG(C)

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries and adds the found ones to LIBS variable
AC_CHECK_LIB(crypto, MD5)
AC_CHECK_LIB(z, deflate)

# Checks for header files.
AC_CHECK_HEADERS([openssl/sha.h])
AC_CHECK_HEADERS([openssl/md5.h])
AC_CHECK_HEADERS([openssl/des.h])
AM_CONDITIONAL([COMPILE_ANONYMIZER], [test "$ac_cv_header_openssl_des_h" = "yes"])

AC_CHECK_HEADERS([zlib.h])

AC_OUTPUT(Makefile)

if test "${ac_cv_lib_crypto_MD5}" = "no"; then
	AC_MSG_WARN([Seems like crypto library is missing. MD5 and SHA256 hashing support is disabled. You might need to install openssl-devel/libssl-dev package.])
fi

if test "${ac_cv_header_openssl_sha_h}" = "no"; then
	AC_MSG_WARN([Seems like openssl/sha.h is missing. SHA256 hashing support is disabled. You might need to install openssl-devel/libssl-dev package.])
fi

if test "${ac_cv_header_openssl_md5_h}" = "no"; then
	AC_MSG_WARN([Seems like openssl/md5.h header is missing. MD5 hashing support is disabled. You might need to install openssl-devel/libssl-dev package.])
fi

if test "${ac_cv_lib_z_deflate}" = "no"; then
	AC_MSG_WARN([Seems like zlib library is missing. Compression ratio computation is disabled. You might need to install zlib-devel/zlib1g-dev package.])
fi

if test "${ac_cv_header_zlib_h}" = "no"; then
	AC_MSG_WARN([Seems like zlib.h is missing. Compression support is disabled. You might need to install zlib-devel/zlib1g-dev package.])
fi
