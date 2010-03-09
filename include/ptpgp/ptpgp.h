#ifndef PTPGP_H
#define PTPGP_H

#define PTPGP_VERSION "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h> /* for uint32_t */

#ifndef u8
#define u8 unsigned char
#endif /* u8 */

#include <ptpgp/error.h>
#include <ptpgp/util.h>
#include <ptpgp/tag.h>
#include <ptpgp/packet-header.h>
#include <ptpgp/stream-parser.h>
#include <ptpgp/armor-parser.h>
#include <ptpgp/base64.h>
#include <ptpgp/packet.h>
#include <ptpgp/packet-parser.h>
#include <ptpgp/signature-type.h>

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* PTPGP_H */
