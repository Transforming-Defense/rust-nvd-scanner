VULNERABILITY SCAN REPORT
SBOM: sample-sbom-cdx.json
Date: 2026-02-15 17:49:03 UTC
Scan Time: 140.93ms
Vulnerabilities: 56
CISA KEV Matches: 0 of 56 in Known Exploited Vulnerabilities catalog
Min Severity: 0.0

============================================================

Critical (9.0+): 5
High (7.0-8.9):  21
Medium (4.0-6.9): 25
Low (0.0-3.9):   5

------------------------------------------------------------

1. CVE-2022-48174 | busybox 1.37.0-r20 | CVSS: 9.8
   There is a stack overflow vulnerability in ash.c:6030 in busybox before 1.35. In the environment of Internet of Vehicles, this vulnerability can be executed from command to arbitrary code execution.

2. CVE-2022-32221 | curl 8.14.1-r2 | CVSS: 9.8
   When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same hand...

3. CVE-2021-20232 | gnutls 3.8.8-r0 | CVSS: 9.8
   A flaw was found in gnutls. A use after free issue in client_send_params in lib/ext/pre_shared_key.c may lead to memory corruption and other potential consequences.

4. CVE-2025-15467 | openssl 3.5.4-r0 | CVSS: 9.8
   Issue summary: Parsing CMS AuthEnvelopedData message with maliciously
crafted AEAD parameters can trigger a stack buffer overflow.

Impact summary: A stack buffer overflow may lead to a crash, causing...

5. CVE-2025-66565 | utils 2.40.13 | CVSS: 9.3
   Fiber Utils is a collection of common functions created for Fiber. In versions 2.0.0-rc.3 and below, when the system's cryptographic random number generator (crypto/rand) fails, both functions silentl...

6. CVE-2023-27533 | curl 8.14.1-r2 | CVSS: 8.8
   A vulnerability in input validation exists in curl <8.0 during communication using the TELNET protocol may allow an attacker to pass on maliciously crafted user name and "telnet options" during server...

7. CVE-2016-9842 | zlib 1.3.1-r2 | CVSS: 8.8
   The inflateMark function in inflate.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact via vectors involving left shifts of negative integers.

8. CVE-2022-4904 | c-ares 1.34.6-r0 | CVSS: 8.6
   A flaw was found in the c-ares package. The ares_set_sortlist is missing checks about the validity of the input string, which allows a possible arbitrary length stack overflow. This issue may cause a ...

9. CVE-2021-3517 | openjdk 21.0.9+10-LTS | CVSS: 8.6
   There is a flaw in the xml entity encoding functionality of libxml2 in versions before 2.9.11. An attacker who is able to supply a crafted file to be processed by an application linked with the affect...

10. CVE-2026-24882 | gnupg 2.4.7-r0 | CVSS: 8.4
   In GnuPG before 2.5.17, a stack-based buffer overflow exists in tpm2daemon during handling of the PKDECRYPT command for TPM-backed RSA and ECC keys.

11. CVE-2026-25646 | libpng 1.6.53-r0 | CVSS: 8.3
   LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. Prior to 1.6.55, an out-of-bounds read vulnerability exists ...

12. CVE-2026-24881 | gnupg 2.4.7-r0 | CVSS: 8.1
   In GnuPG before 2.5.17, a crafted CMS (S/MIME) EnvelopedData message carrying an oversized wrapped session key can cause a stack-based buffer overflow in gpg-agent during PKDECRYPT--kem=CMS handling. ...

13. CVE-2025-26519 | musl 1.2.5-r10 | CVSS: 8.1
   musl libc 0.9.13 through 1.2.5 before 1.2.6 has an out-of-bounds write vulnerability when an attacker can trigger iconv conversion of untrusted EUC-KR text to UTF-8.

14. CVE-2021-28831 | busybox 1.37.0-r20 | CVSS: 7.5
   decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.

15. CVE-2016-6301 | busybox 1.37.0-r20 | CVSS: 7.5
   The recv_and_process_client_pkt function in networking/ntpd.c in busybox allows remote attackers to cause a denial of service (CPU and bandwidth consumption) via a forged NTP packet, which triggers a ...

16. CVE-2022-43551 | curl 8.14.1-r2 | CVSS: 7.5
   A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP. Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-...

17. CVE-2023-38039 | curl 8.14.1-r2 | CVSS: 7.5
   When curl retrieves an HTTP response, it stores the incoming headers so that
they can be accessed later via the libcurl headers API.

However, curl did not have a limit in how many or how large header...

18. CVE-2022-42916 | curl 8.14.1-r2 | CVSS: 7.5
   In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext...

19. CVE-2025-9086 | curl 8.14.1-r2 | CVSS: 7.5
   1. A cookie is set using the `secure` keyword for `https://target` 
 2. curl is redirected to or otherwise made to speak with `http://target` (same 
   hostname, but using clear text HTTP) using the s...

20. CVE-2022-2509 | gnutls 3.8.8-r0 | CVSS: 7.5
   A vulnerability found in gnutls. This security flaw happens because of a double free error occurs during verification of pkcs7 signatures in gnutls_pkcs7_verify function.

21. CVE-2021-33560 | libgcrypt 1.10.3-r1 | CVSS: 7.5
   Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appr...

22. CVE-2025-69420 | openssl 3.5.4-r0 | CVSS: 7.5
   Issue summary: A type confusion vulnerability exists in the TimeStamp Response
verification code where an ASN1_TYPE union member is accessed without first
validating the type, causing an invalid or NU...

23. CVE-2025-69421 | openssl 3.5.4-r0 | CVSS: 7.5
   Issue summary: Processing a malformed PKCS#12 file can trigger a NULL pointer
dereference in the PKCS12_item_decrypt_d2i_ex() function.

Impact summary: A NULL pointer dereference can trigger a crash ...

24. CVE-2023-5363 | openssl 3.5.4-r0 | CVSS: 7.5
   Issue summary: A bug has been identified in the processing of key and
initialisation vector (IV) lengths.  This can lead to potential truncation
or overruns during the initialisation of some symmetric...

25. CVE-2025-69419 | openssl 3.5.4-r0 | CVSS: 7.4
   Issue summary: Calling PKCS12_get_friendlyname() function on a maliciously
crafted PKCS#12 file with a BMPString (UTF-16BE) friendly name containing
non-ASCII BMP code point can trigger a one byte wri...

26. CVE-2025-66293 | libpng 1.6.53-r0 | CVSS: 7.1
   LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. Prior to 1.6.52, an out-of-bounds read vulnerability in libp...

27. CVE-2026-22801 | libpng 1.6.53-r0 | CVSS: 6.8
   LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From 1.6.26 to 1.6.53, there is an integer truncation in the...

28. CVE-2023-23915 | curl 8.14.1-r2 | CVSS: 6.5
   A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause HSTS functionality to behave incorrectly when multiple URLs are requested in parallel. Using it...

29. CVE-2025-32988 | gnutls 3.8.8-r0 | CVSS: 6.5
   A flaw was found in GnuTLS. A double-free vulnerability exists in GnuTLS due to incorrect ownership handling in the export logic of Subject Alternative Name (SAN) entries containing an otherName. If t...

30. CVE-2025-14017 | curl 8.14.1-r2 | CVSS: 6.3
   When doing multi-threaded LDAPS transfers (LDAP over TLS) with libcurl,
changing TLS options in one thread would inadvertently change them globally
and therefore possibly also affect other concurrentl...

31. CVE-2026-22695 | libpng 1.6.53-r0 | CVSS: 6.1
   LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From 1.6.51 to 1.6.53, there is a heap buffer over-read in t...

32. CVE-2025-11187 | openssl 3.5.4-r0 | CVSS: 6.1
   Issue summary: PBMAC1 parameters in PKCS#12 files are missing validation
which can trigger a stack-based buffer overflow, invalid pointer or NULL
pointer dereference during MAC verification.

Impact s...

33. CVE-2025-62408 | c-ares 1.34.6-r0 | CVSS: 5.9
   c-ares is an asynchronous resolver library. Versions 1.32.3 through 1.34.5  terminate a query after maximum attempts when using read_answer() and process_answer(), which can cause a Denial of Service....

34. CVE-2025-13034 | curl 8.14.1-r2 | CVSS: 5.9
   When using `CURLOPT_PINNEDPUBLICKEY` option with libcurl or `--pinnedpubkey`
with the curl tool,curl should check the public key of the server certificate
to verify the peer.

This check was skipped i...

35. CVE-2025-66199 | openssl 3.5.4-r0 | CVSS: 5.9
   Issue summary: A TLS 1.3 connection using certificate compression can be
forced to allocate a large buffer before decompression without checking
against the configured certificate size limit.

Impact ...

36. CVE-2025-15468 | openssl 3.5.4-r0 | CVSS: 5.9
   Issue summary: If an application using the SSL_CIPHER_find() function in
a QUIC protocol client or server receives an unknown cipher suite from
the peer, a NULL dereference occurs.

Impact summary: A ...

37. CVE-2025-28164 | libpng 1.6.53-r0 | CVSS: 5.5
   Buffer Overflow vulnerability in libpng 1.6.43-1.6.46 allows a local attacker to cause a denial of service via png_create_read_struct() function.

38. CVE-2025-28162 | libpng 1.6.53-r0 | CVSS: 5.5
   Buffer Overflow vulnerability in libpng 1.6.43-1.6.46 allows a local attacker to cause a denial of service via the pngimage with AddressSanitizer (ASan), the program leaks memory in various locations,...

39. CVE-2025-15469 | openssl 3.5.4-r0 | CVSS: 5.5
   Issue summary: The 'openssl dgst' command-line tool silently truncates input
data to 16MB when using one-shot signing algorithms and reports success instead
of an error.

Impact summary: A user signin...

40. CVE-2026-22795 | openssl 3.5.4-r0 | CVSS: 5.5
   Issue summary: An invalid or NULL pointer dereference can happen in
an application processing a malformed PKCS#12 file.

Impact summary: An application processing a malformed PKCS#12 file can be
cause...

41. CVE-2025-10148 | curl 8.14.1-r2 | CVSS: 5.3
   curl's websocket code did not update the 32 bit mask pattern for each new
 outgoing frame as the specification says. Instead it used a fixed mask that
persisted and was used throughout the entire conn...

42. CVE-2025-14819 | curl 8.14.1-r2 | CVSS: 5.3
   When doing TLS related transfers with reused easy or multi handles and
altering the  `CURLSSLOPT_NO_PARTIALCHAIN` option, libcurl could accidentally
reuse a CA store cached in memory for which the par...

43. CVE-2025-14524 | curl 8.14.1-r2 | CVSS: 5.3
   When an OAuth2 bearer token is used for an HTTP(S) transfer, and that transfer
performs a cross-protocol redirect to a second URL that uses an IMAP, LDAP,
POP3 or SMTP scheme, curl might wrongly pass ...

44. CVE-2025-15079 | curl 8.14.1-r2 | CVSS: 5.3
   When doing SSH-based transfers using either SCP or SFTP, and setting the
known_hosts file, libcurl could still mistakenly accept connecting to hosts
*not present* in the specified file if they were ad...

45. CVE-2023-46219 | curl 8.14.1-r2 | CVSS: 5.3
   When saving HSTS data to an excessively long file name, curl could end up
removing all contents, making subsequent requests using that file unaware of
the HSTS status they should otherwise use.

46. CVE-2020-13956 | httpclient 4.5.13 | CVSS: 5.3
   Apache HttpClient versions prior to version 4.5.13 and 5.0.3 can misinterpret malformed authority component in request URIs passed to the library as java.net.URI object and pick the wrong target host ...

47. CVE-2026-22796 | openssl 3.5.4-r0 | CVSS: 5.3
   Issue summary: A type confusion vulnerability exists in the signature
verification of signed PKCS#7 data where an ASN1_TYPE union member is
accessed without first validating the type, causing an inval...

48. CVE-2023-5678 | openssl 3.5.4-r0 | CVSS: 5.3
   Issue summary: Generating excessively long X9.42 DH keys or checking
excessively long X9.42 DH keys or parameters may be very slow.

Impact summary: Applications that use the functions DH_generate_key...

49. CVE-2025-68160 | openssl 3.5.4-r0 | CVSS: 4.7
   Issue summary: Writing large, newline-free data into a BIO chain using the
line-buffering filter where the next BIO performs short writes can trigger
a heap-based out-of-bounds write.

Impact summary:...

50. CVE-2025-10966 | curl 8.14.1-r2 | CVSS: 4.3
   curl's code for managing SSH connections when SFTP was done using the wolfSSH
powered backend was flawed and missed host verification mechanisms.

This prevents curl from detecting MITM attackers and ...

51. CVE-2025-69418 | openssl 3.5.4-r0 | CVSS: 4.0
   Issue summary: When using the low-level OCB API directly with AES-NI or<br>other hardware-accelerated code paths, inputs whose length is not a multiple<br>of 16 bytes can leave the final partial block...

52. CVE-2023-28322 | curl 8.14.1-r2 | CVSS: 3.7
   An information disclosure vulnerability exists in curl <v8.1.0 when doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to ask for data to send, even when...

53. CVE-2026-24883 | gnupg 2.4.7-r0 | CVSS: 3.7
   In GnuPG before 2.5.17, a long signature packet length causes parse_signature to return success with sig->data[] set to a NULL value, leading to a denial of service (application crash).

54. CVE-2025-15224 | curl 8.14.1-r2 | CVSS: 3.1
   When doing SSH-based transfers using either SCP or SFTP, and asked to do
public key authentication, curl would wrongly still ask and authenticate using
a locally running SSH agent.

55. CVE-2026-24515 | libexpat 2.7.3-r0 | CVSS: 2.9
   In libexpat before 2.7.4, XML_ExternalEntityParserCreate does not copy unknown encoding handler user data.

56. CVE-2025-66382 | libexpat 2.7.3-r0 | CVSS: 2.9
   In libexpat through 2.7.3, a crafted file with an approximate size of 2 MiB can lead to dozens of seconds of processing time.

