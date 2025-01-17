/* Object identifiers (OIDs) used by strongSwan
 * Copyright (C) 2003-2008 Andreas Steffen
 * 
 * This file has been automatically generated by the script oid.pl
 * Do not edit manually!
 */

#include <utils/utils.h>

#ifndef OID_H_
#define OID_H_

typedef struct {
    u_char octet;
    u_int  next;
    u_int  down;
    u_int  level;
    const u_char *name;
} oid_t;

extern const oid_t oid_names[];

#define OID_UNKNOWN							-1
#define OID_NAME_DISTINGUISHER				6
#define OID_PILOT_USERID					16
#define OID_PILOT_DOMAIN_COMPONENT			17
#define OID_COMMON_NAME						20
#define OID_SURNAME							21
#define OID_SERIAL_NUMBER					22
#define OID_COUNTRY							23
#define OID_LOCALITY						24
#define OID_STATE_OR_PROVINCE				25
#define OID_STREET_ADDRESS					26
#define OID_ORGANIZATION					27
#define OID_ORGANIZATION_UNIT				28
#define OID_TITLE							29
#define OID_DESCRIPTION						30
#define OID_POSTAL_ADDRESS					31
#define OID_POSTAL_CODE						32
#define OID_USER_CERTIFICATE				33
#define OID_NAME							34
#define OID_GIVEN_NAME						35
#define OID_INITIALS						36
#define OID_UNIQUE_IDENTIFIER				37
#define OID_DN_QUALIFIER					38
#define OID_DMD_NAME						39
#define OID_PSEUDONYM						40
#define OID_ROLE							41
#define OID_SUBJECT_KEY_ID					44
#define OID_KEY_USAGE						45
#define OID_SUBJECT_ALT_NAME				47
#define OID_BASIC_CONSTRAINTS				49
#define OID_CRL_NUMBER						50
#define OID_CRL_REASON_CODE					51
#define OID_DELTA_CRL_INDICATOR				54
#define OID_ISSUING_DIST_POINT				55
#define OID_NAME_CONSTRAINTS				57
#define OID_CRL_DISTRIBUTION_POINTS			58
#define OID_CERTIFICATE_POLICIES			59
#define OID_ANY_POLICY						60
#define OID_POLICY_MAPPINGS					61
#define OID_AUTHORITY_KEY_ID				62
#define OID_POLICY_CONSTRAINTS				63
#define OID_EXTENDED_KEY_USAGE				64
#define OID_FRESHEST_CRL					66
#define OID_INHIBIT_ANY_POLICY				67
#define OID_TARGET_INFORMATION				68
#define OID_NO_REV_AVAIL					69
#define OID_CAMELLIA128_CBC					80
#define OID_CAMELLIA192_CBC					81
#define OID_CAMELLIA256_CBC					82
#define OID_RSA_ENCRYPTION					95
#define OID_MD2_WITH_RSA					96
#define OID_MD5_WITH_RSA					97
#define OID_SHA1_WITH_RSA					98
#define OID_RSAES_OAEP						99
#define OID_MGF1							100
#define OID_RSASSA_PSS						102
#define OID_SHA256_WITH_RSA					103
#define OID_SHA384_WITH_RSA					104
#define OID_SHA512_WITH_RSA					105
#define OID_SHA224_WITH_RSA					106
#define OID_PBE_MD5_DES_CBC					108
#define OID_PBE_SHA1_DES_CBC				109
#define OID_PBKDF2							110
#define OID_PBES2							111
#define OID_PKCS7_DATA						113
#define OID_PKCS7_SIGNED_DATA				114
#define OID_PKCS7_ENVELOPED_DATA			115
#define OID_PKCS7_SIGNED_ENVELOPED_DATA		116
#define OID_PKCS7_DIGESTED_DATA				117
#define OID_PKCS7_ENCRYPTED_DATA			118
#define OID_EMAIL_ADDRESS					120
#define OID_UNSTRUCTURED_NAME				121
#define OID_PKCS9_CONTENT_TYPE				122
#define OID_PKCS9_MESSAGE_DIGEST			123
#define OID_PKCS9_SIGNING_TIME				124
#define OID_CHALLENGE_PASSWORD				126
#define OID_UNSTRUCTURED_ADDRESS			127
#define OID_EXTENSION_REQUEST				128
#define OID_X509_CERTIFICATE				131
#define OID_PBE_SHA1_RC4_128				135
#define OID_PBE_SHA1_RC4_40					136
#define OID_PBE_SHA1_3DES_CBC				137
#define OID_PBE_SHA1_3DES_2KEY_CBC			138
#define OID_PBE_SHA1_RC2_CBC_128			139
#define OID_PBE_SHA1_RC2_CBC_40				140
#define OID_P12_KEY_BAG						143
#define OID_P12_PKCS8_KEY_BAG				144
#define OID_P12_CERT_BAG					145
#define OID_P12_CRL_BAG						146
#define OID_MD2								150
#define OID_MD5								151
#define OID_HMAC_SHA1						152
#define OID_HMAC_SHA224						153
#define OID_HMAC_SHA256						154
#define OID_HMAC_SHA384						155
#define OID_HMAC_SHA512						156
#define OID_HMAC_SHA512_224					157
#define OID_HMAC_SHA512_256					158
#define OID_3DES_EDE_CBC					160
#define OID_EC_PUBLICKEY					164
#define OID_C2PNB163V1						167
#define OID_C2PNB163V2						168
#define OID_C2PNB163V3						169
#define OID_C2PNB176W1						170
#define OID_C2PNB191V1						171
#define OID_C2PNB191V2						172
#define OID_C2PNB191V3						173
#define OID_C2PNB191V4						174
#define OID_C2PNB191V5						175
#define OID_C2PNB208W1						176
#define OID_C2PNB239V1						177
#define OID_C2PNB239V2						178
#define OID_C2PNB239V3						179
#define OID_C2PNB239V4						180
#define OID_C2PNB239V5						181
#define OID_C2PNB272W1						182
#define OID_C2PNB304W1						183
#define OID_C2PNB359V1						184
#define OID_C2PNB368W1						185
#define OID_C2PNB431R1						186
#define OID_PRIME192V1						188
#define OID_PRIME192V2						189
#define OID_PRIME192V3						190
#define OID_PRIME239V1						191
#define OID_PRIME239V2						192
#define OID_PRIME239V3						193
#define OID_PRIME256V1						194
#define OID_ECDSA_WITH_SHA1					196
#define OID_ECDSA_WITH_SHA224				198
#define OID_ECDSA_WITH_SHA256				199
#define OID_ECDSA_WITH_SHA384				200
#define OID_ECDSA_WITH_SHA512				201
#define OID_DILITHIUM_2						212
#define OID_DILITHIUM_3						214
#define OID_DILITHIUM_5						216
#define OID_MS_CERT_TYPE_EXT				224
#define OID_MS_SMARTCARD_LOGON				225
#define OID_USER_PRINCIPAL_NAME				226
#define OID_STRONGSWAN						232
#define OID_TCGID							240
#define OID_BLOWFISH_CBC					244
#define OID_AUTHORITY_INFO_ACCESS			288
#define OID_IP_ADDR_BLOCKS					290
#define OID_POLICY_QUALIFIER_CPS			293
#define OID_POLICY_QUALIFIER_UNOTICE		294
#define OID_SERVER_AUTH						296
#define OID_CLIENT_AUTH						297
#define OID_OCSP_SIGNING					304
#define OID_XMPP_ADDR						310
#define OID_AUTHENTICATION_INFO				314
#define OID_ACCESS_IDENTITY					315
#define OID_CHARGING_IDENTITY				316
#define OID_GROUP							317
#define OID_OCSP							320
#define OID_BASIC							321
#define OID_NONCE							322
#define OID_CRL								323
#define OID_RESPONSE						324
#define OID_NO_CHECK						325
#define OID_ARCHIVE_CUTOFF					326
#define OID_SERVICE_LOCATOR					327
#define OID_CA_ISSUERS						328
#define OID_IKE_INTERMEDIATE				333
#define OID_DES_CBC							337
#define OID_SHA1							338
#define OID_SHA1_WITH_RSA_OIW				339
#define OID_ECGDSA_PUBKEY					358
#define OID_ECGDSA_SIG_WITH_RIPEMD160		361
#define OID_ECGDSA_SIG_WITH_SHA1			362
#define OID_ECGDSA_SIG_WITH_SHA224			363
#define OID_ECGDSA_SIG_WITH_SHA256			364
#define OID_ECGDSA_SIG_WITH_SHA384			365
#define OID_ECGDSA_SIG_WITH_SHA512			366
#define OID_ED25519							387
#define OID_ED448							388
#define OID_SECT163K1						392
#define OID_SECT163R1						393
#define OID_SECT239K1						394
#define OID_SECT113R1						395
#define OID_SECT113R2						396
#define OID_SECT112R1						397
#define OID_SECT112R2						398
#define OID_SECT160R1						399
#define OID_SECT160K1						400
#define OID_SECT256K1						401
#define OID_SECT163R2						402
#define OID_SECT283K1						403
#define OID_SECT283R1						404
#define OID_SECT131R1						405
#define OID_SECT131R2						406
#define OID_SECT193R1						407
#define OID_SECT193R2						408
#define OID_SECT233K1						409
#define OID_SECT233R1						410
#define OID_SECT128R1						411
#define OID_SECT128R2						412
#define OID_SECT160R2						413
#define OID_SECT192K1						414
#define OID_SECT224K1						415
#define OID_SECT224R1						416
#define OID_SECT384R1						417
#define OID_SECT521R1						418
#define OID_SECT409K1						419
#define OID_SECT409R1						420
#define OID_SECT571K1						421
#define OID_SECT571R1						422
#define OID_FALCON_512						426
#define OID_FALCON_1024						427
#define OID_AES128_CBC						436
#define OID_AES128_GCM						437
#define OID_AES128_CCM						438
#define OID_AES192_CBC						439
#define OID_AES192_GCM						440
#define OID_AES192_CCM						441
#define OID_AES256_CBC						442
#define OID_AES256_GCM						443
#define OID_AES256_CCM						444
#define OID_SHA256							446
#define OID_SHA384							447
#define OID_SHA512							448
#define OID_SHA224							449
#define OID_SHA3_224						452
#define OID_SHA3_256						453
#define OID_SHA3_384						454
#define OID_SHA3_512						455
#define OID_ECDSA_WITH_SHA3_224				459
#define OID_ECDSA_WITH_SHA3_256				460
#define OID_ECDSA_WITH_SHA3_384				461
#define OID_ECDSA_WITH_SHA3_512				462
#define OID_RSASSA_PKCS1V15_WITH_SHA3_224	463
#define OID_RSASSA_PKCS1V15_WITH_SHA3_256	464
#define OID_RSASSA_PKCS1V15_WITH_SHA3_384	465
#define OID_RSASSA_PKCS1V15_WITH_SHA3_512	466
#define OID_NS_REVOCATION_URL				472
#define OID_NS_CA_REVOCATION_URL			473
#define OID_NS_CA_POLICY_URL				474
#define OID_NS_COMMENT						475
#define OID_EMPLOYEE_NUMBER					478
#define OID_PKI_MESSAGE_TYPE				484
#define OID_PKI_STATUS						485
#define OID_PKI_FAIL_INFO					486
#define OID_PKI_SENDER_NONCE				487
#define OID_PKI_RECIPIENT_NONCE				488
#define OID_PKI_TRANS_ID					489
#define OID_TPM_MANUFACTURER				495
#define OID_TPM_MODEL						496
#define OID_TPM_VERSION						497
#define OID_TPM_ID_LABEL					498

#define OID_MAX								499

#endif /* OID_H_ */
