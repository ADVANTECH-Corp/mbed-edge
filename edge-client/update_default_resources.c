
//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2013-2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#include <stdint.h>

#ifdef MBED_CLOUD_DEV_UPDATE_ID
const uint8_t arm_uc_vendor_id[] = {
    0x51, 0xf8, 0x56, 0xa3, 0xc7, 0x56, 0x57, 0xac, 0xae, 0xec, 0x7a, 0x60, 0x78, 0x8f, 0xed, 0xf6
};
const uint16_t arm_uc_vendor_id_size = sizeof(arm_uc_vendor_id);

const uint8_t arm_uc_class_id[]  = {
    0x29, 0x15, 0x2c, 0x10, 0xe5, 0x76, 0x5f, 0x21, 0x8d, 0x9b, 0xe0, 0x83, 0x4b, 0x1a, 0xad, 0x69
};
const uint16_t arm_uc_class_id_size = sizeof(arm_uc_class_id);
#endif

#ifdef MBED_CLOUD_DEV_UPDATE_CERT
const uint8_t arm_uc_default_fingerprint[] =  {
    0xac, 0x8e, 0x39, 0x4e, 0x2e, 0xdc, 0x1a, 0x32, 0x99, 0xd4, 0xf8, 0xa6, 0x70, 0x80, 0x46, 0x98,
    0x3, 0xb6, 0xf9, 0x83, 0x94, 0x23, 0x48, 0x35, 0x7b, 0x50, 0x16, 0x44, 0x27, 0x44, 0xdc, 0xce
};
const uint16_t arm_uc_default_fingerprint_size =
    sizeof(arm_uc_default_fingerprint);

const uint8_t arm_uc_default_subject_key_identifier[] =  {
    0xd0, 0x7, 0xcb, 0x96, 0xbc, 0xda, 0x34, 0xd3, 0xf8, 0x64, 0xec, 0x4d, 0x81, 0x16, 0x9b, 0xa9,
    0xd3, 0xe6, 0x27, 0x3e
};
const uint16_t arm_uc_default_subject_key_identifier_size =
    sizeof(arm_uc_default_subject_key_identifier);

const uint8_t arm_uc_default_certificate[] = {
    0x30, 0x82, 0x1, 0x8b, 0x30, 0x82, 0x1, 0x32, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x13, 0x1b,
    0x5c, 0xe0, 0x36, 0x9b, 0xd6, 0x52, 0x8b, 0x41, 0x7d, 0x3c, 0x3d, 0x77, 0xce, 0x1a, 0x39, 0x74,
    0x41, 0xe7, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x19,
    0x31, 0x17, 0x30, 0x15, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0xe, 0x61, 0x64, 0x76, 0x61, 0x6e,
    0x74, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x30, 0x1e, 0x17, 0xd, 0x31, 0x38, 0x30,
    0x35, 0x30, 0x38, 0x30, 0x35, 0x35, 0x32, 0x33, 0x32, 0x5a, 0x17, 0xd, 0x31, 0x38, 0x30, 0x38,
    0x30, 0x36, 0x30, 0x35, 0x35, 0x32, 0x33, 0x32, 0x5a, 0x30, 0x19, 0x31, 0x17, 0x30, 0x15, 0x6,
    0x3, 0x55, 0x4, 0x3, 0xc, 0xe, 0x61, 0x64, 0x76, 0x61, 0x6e, 0x74, 0x65, 0x63, 0x68, 0x2e,
    0x63, 0x6f, 0x6d, 0x20, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2,
    0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0xc4,
    0x24, 0x13, 0x61, 0x97, 0x2a, 0xd5, 0x2f, 0x73, 0x78, 0xf4, 0x18, 0x86, 0xe9, 0x22, 0x58, 0xe2,
    0x2a, 0x75, 0xe1, 0x16, 0x8a, 0xe2, 0x81, 0xd2, 0x58, 0x47, 0x86, 0x82, 0x24, 0xe2, 0x78, 0xff,
    0xae, 0xb7, 0x4c, 0x89, 0x6e, 0x71, 0xab, 0x6b, 0x90, 0xd0, 0x84, 0xe9, 0xc7, 0xf4, 0x90, 0xc3,
    0x95, 0x8e, 0x6c, 0x6b, 0x95, 0xb1, 0xc1, 0xa, 0x38, 0xad, 0xdd, 0x8e, 0x78, 0xed, 0x9b, 0xa3,
    0x59, 0x30, 0x57, 0x30, 0xb, 0x6, 0x3, 0x55, 0x1d, 0xf, 0x4, 0x4, 0x3, 0x2, 0x7, 0x80,
    0x30, 0x14, 0x6, 0x3, 0x55, 0x1d, 0x11, 0x4, 0xd, 0x30, 0xb, 0x82, 0x9, 0x6c, 0x6f, 0x63,
    0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x13, 0x6, 0x3, 0x55, 0x1d, 0x25, 0x4, 0xc, 0x30,
    0xa, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x3, 0x30, 0x1d, 0x6, 0x3, 0x55,
    0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0xd0, 0x7, 0xcb, 0x96, 0xbc, 0xda, 0x34, 0xd3, 0xf8, 0x64,
    0xec, 0x4d, 0x81, 0x16, 0x9b, 0xa9, 0xd3, 0xe6, 0x27, 0x3e, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x3, 0x47, 0x0, 0x30, 0x44, 0x2, 0x20, 0x38, 0xba, 0x75,
    0xb9, 0xda, 0xf4, 0x9d, 0x5, 0xff, 0x12, 0x2e, 0x4e, 0xc4, 0x32, 0xb5, 0x1f, 0xd6, 0xaf, 0xa8,
    0x4a, 0xc1, 0xbf, 0xf6, 0x21, 0x62, 0x8, 0x3a, 0x28, 0x95, 0x49, 0x58, 0xd8, 0x2, 0x20, 0x37,
    0x76, 0x86, 0xbf, 0xce, 0xd5, 0xad, 0x8e, 0x14, 0x5a, 0xe9, 0xd0, 0x87, 0x59, 0x7a, 0x81, 0x2,
    0xa5, 0x6, 0x4f, 0xf0, 0x23, 0xc8, 0x36, 0x46, 0xf5, 0x51, 0xc2, 0x6f, 0xa6, 0x85, 0x5a
};
const uint16_t arm_uc_default_certificate_size = sizeof(arm_uc_default_certificate);
#endif


#ifdef MBED_CLOUD_DEV_UPDATE_PSK
const uint8_t arm_uc_default_psk[] = {
    0x83, 0x11, 0x85, 0xaa, 0xff, 0x6d, 0x45, 0xf7, 0xab, 0xa7, 0xdd, 0xd, 0x40, 0x31, 0xd5, 0x12
};
const uint16_t arm_uc_default_psk_bits = 128;
#endif
