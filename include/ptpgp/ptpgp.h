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

#ifndef bool
#define bool char
#endif /* bool */

#include <ptpgp/error.h>
#include <ptpgp/util.h>

#include <ptpgp/tag.h>
#include <ptpgp/type.h>
#include <ptpgp/key-flag.h>
#include <ptpgp/mpi.h>
#include <ptpgp/pk-key.h>

#include <ptpgp/s2k.h>
#include <ptpgp/crc24.h>
#include <ptpgp/base64.h>

#include <ptpgp/engine-structs.h>
#include <ptpgp/engine-hash.h>
#include <ptpgp/engine-encrypt.h>
#include <ptpgp/engine-random.h>
#include <ptpgp/engine-pk.h>
#include <ptpgp/engine.h>
#include <ptpgp/openssl.h>
#include <ptpgp/gcrypt.h>

#include <ptpgp/packet-header.h>
#include <ptpgp/uri-parser.h>
#include <ptpgp/stream-parser.h>
#include <ptpgp/armor-parser.h>
#include <ptpgp/armor-encoder.h>
#include <ptpgp/signature-type.h>
#include <ptpgp/packet.h>
#include <ptpgp/signature-subpacket.h>
#include <ptpgp/signature-subpacket-parser.h>
#include <ptpgp/packet-parser.h>

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* PTPGP_H */
