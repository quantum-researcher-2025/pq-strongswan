BEGIN {
D["PACKAGE_NAME"]=" \"strongSwan\""
D["PACKAGE_TARNAME"]=" \"strongswan\""
D["PACKAGE_VERSION"]=" \"6.0.0beta6\""
D["PACKAGE_STRING"]=" \"strongSwan 6.0.0beta6\""
D["PACKAGE_BUGREPORT"]=" \"\""
D["PACKAGE_URL"]=" \"\""
D["PACKAGE"]=" \"strongswan\""
D["VERSION"]=" \"6.0.0beta6\""
D["CONFIG_H_INCLUDED"]=" /**/"
D["HAVE_STDIO_H"]=" 1"
D["HAVE_STDLIB_H"]=" 1"
D["HAVE_STRING_H"]=" 1"
D["HAVE_INTTYPES_H"]=" 1"
D["HAVE_STDINT_H"]=" 1"
D["HAVE_STRINGS_H"]=" 1"
D["HAVE_SYS_STAT_H"]=" 1"
D["HAVE_SYS_TYPES_H"]=" 1"
D["HAVE_UNISTD_H"]=" 1"
D["STDC_HEADERS"]=" 1"
D["HAVE_DLFCN_H"]=" 1"
D["LT_OBJDIR"]=" \".libs/\""
D["HAVE__BOOL"]=" 1"
D["HAVE_STDBOOL_H"]=" 1"
D["HAVE_ALLOCA_H"]=" 1"
D["HAVE_ALLOCA"]=" 1"
D["HAVE_DECL_STRERROR_R"]=" 1"
D["HAVE_STRERROR_R"]=" 1"
D["HAVE_BACKTRACE"]=" 1"
D["HAVE_DLADDR"]=" /**/"
D["HAVE_CONDATTR_CLOCK_MONOTONIC"]=" /**/"
D["HAVE_PTHREAD_CONDATTR_INIT"]=" 1"
D["HAVE_PTHREAD_CANCEL"]=" 1"
D["HAVE_PTHREAD_RWLOCK_INIT"]=" 1"
D["HAVE_PTHREAD_SPIN_INIT"]=" 1"
D["HAVE_SEM_TIMEDWAIT"]=" 1"
D["HAVE_GETTID"]=" /**/"
D["HAVE_QSORT_R"]=" /**/"
D["HAVE_QSORT_R_GNU"]=" /**/"
D["HAVE_PRCTL"]=" 1"
D["HAVE_MALLINFO"]=" 1"
D["HAVE_MALLINFO2"]=" 1"
D["HAVE_GETPASS"]=" 1"
D["HAVE_CLOSEFROM"]=" 1"
D["HAVE_GETPWNAM_R"]=" 1"
D["HAVE_GETGRNAM_R"]=" 1"
D["HAVE_GETPWUID_R"]=" 1"
D["HAVE_CHOWN"]=" 1"
D["HAVE_FMEMOPEN"]=" 1"
D["HAVE_MMAP"]=" 1"
D["HAVE_MEMRCHR"]=" 1"
D["HAVE_SETLINEBUF"]=" 1"
D["HAVE_STRPTIME"]=" 1"
D["HAVE_DIRFD"]=" 1"
D["HAVE_SIGWAITINFO"]=" 1"
D["HAVE_EXPLICIT_BZERO"]=" 1"
D["HAVE_SYSLOG"]=" /**/"
D["HAVE_SYS_SYSCALL_H"]=" 1"
D["HAVE_SYS_PARAM_H"]=" 1"
D["HAVE_GLOB_H"]=" 1"
D["HAVE_LINUX_UDP_H"]=" 1"
D["HAVE_NETINET_IP6_H"]=" 1"
D["HAVE_LINUX_FIB_RULES_H"]=" 1"
D["HAVE_STRUCT_SADB_X_POLICY_SADB_X_POLICY_PRIORITY"]=" 1"
D["HAVE_IN6ADDR_ANY"]=" /**/"
D["HAVE_IN6_PKTINFO"]=" /**/"
D["HAVE_IPSEC_MODE_BEET"]=" /**/"
D["HAVE_IPSEC_DIR_FWD"]=" /**/"
D["HAVE_RTA_TABLE"]=" /**/"
D["HAVE_INT128"]=" /**/"
D["HAVE_GCC_SYNC_OPERATIONS"]=" /**/"
D["HAVE_PRINTF_SPECIFIER"]=" /**/"
D["HAVE_CLOCK_GETTIME"]=" 1"
D["HAVE_LIBOQS"]=" 1"
D["USE_IKEV1"]=" /**/"
D["USE_IKEV2"]=" /**/"
  for (key in D) D_is_set[key] = 1
  FS = ""
}
/^[\t ]*#[\t ]*(define|undef)[\t ]+[_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ][_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]*([\t (]|$)/ {
  line = $ 0
  split(line, arg, " ")
  if (arg[1] == "#") {
    defundef = arg[2]
    mac1 = arg[3]
  } else {
    defundef = substr(arg[1], 2)
    mac1 = arg[2]
  }
  split(mac1, mac2, "(") #)
  macro = mac2[1]
  prefix = substr(line, 1, index(line, defundef) - 1)
  if (D_is_set[macro]) {
    # Preserve the white space surrounding the "#".
    print prefix "define", macro P[macro] D[macro]
    next
  } else {
    # Replace #undef with comments.  This is necessary, for example,
    # in the case of _POSIX_SOURCE, which is predefined and required
    # on some systems where configure will not decide to define it.
    if (defundef == "undef") {
      print "/*", prefix defundef, macro, "*/"
      next
    }
  }
}
{ print }
