#include "internal.h"

static struct {
  ptpgp_signature_type_t type;
  char *name, *description;
} types[] = {{ 
  0x00, "Signature of a Binary Document",
  "This means the signer owns it, created it, or certifies that it\n"
  "has not been modified.\n"
}, {
  0x01, "Signature of a Canonical Text Document",
  "This means the signer owns it, created it, or certifies that it\n"
  "has not been modified.  The signature is calculated over the text\n"
  "data with its line endings converted to <CR><LF>.\n"
}, {
  0x02, "Standalone Signature",
  "This signature is a signature of only its own subpacket contents.\n"
  "It is calculated identically to a signature over a zero-length\n"
  "binary document.  Note that it doesn't make sense to have a V3\n"
  "standalone signature.\n"
}, {
  0x10, "Generic Certification of a User ID and Public-Key Packet",
  "The issuer of this certification does not make any particular\n"
  "assertion as to how well the certifier has checked that the owner\n"
  "of the key is in fact the person described by the User ID.\n"
}, {
  0x11, "Persona Certification of a User ID and Public-Key Packet",
  "The issuer of this certification has not done any verification of\n"
  "the claim that the owner of this key is the User ID specified.\n"
}, {
  0x12, "Casual Certification of a User ID and Public-Key Packet",
  "The issuer of this certification has done some casual\n"
  "verification of the claim of identity.\n"
}, {
  0x13, "Positive Certification of a User ID and Public-Key Packet",
  "The issuer of this certification has done substantial\n"
  "verification of the claim of identity.\n"
  "\n"
  "Most OpenPGP implementations make their \"key signatures\" as 0x10\n"
  "certifications.  Some implementations can issue 0x11-0x13\n"
  "certifications, but few differentiate between the types.\n"
}, {
  0x18, "Subkey Binding Signature",
  "This signature is a statement by the top-level signing key that\n"
  "indicates that it owns the subkey.  This signature is calculated\n"
  "directly on the primary key and subkey, and not on any User ID or\n"
  "other packets.  A signature that binds a signing subkey MUST have\n"
  "an Embedded Signature subpacket in this binding signature that\n"
  "contains a 0x19 signature made by the signing subkey on the\n"
  "primary key and subkey.\n"
}, {
  0x19, "Primary Key Binding Signature",
  "This signature is a statement by a signing subkey, indicating\n"
  "that it is owned by the primary key and subkey.  This signature\n"
  "is calculated the same way as a 0x18 signature: directly on the\n"
  "primary key and subkey, and not on any User ID or other packets.\n"
}, {
  0x1F, "Signature Directly on a Key",
  "This signature is calculated directly on a key.  It binds the\n"
  "information in the Signature subpackets to the key, and is\n"
  "appropriate to be used for subpackets that provide information\n"
  "about the key, such as the Revocation Key subpacket.  It is also\n"
  "appropriate for statements that non-self certifiers want to make\n"
  "about the key itself, rather than the binding between a key and a\n"
  "name.\n"
}, {
  0x20, "Key Revocation Signature",
  "The signature is calculated directly on the key being revoked.  A\n"
  "revoked key is not to be used.  Only revocation signatures by the\n"
  "key being revoked, or by an authorized revocation key, should be\n"
  "considered valid revocation signatures.\n"
}, {
  0x28, "Subkey Revocation Signature",
  "The signature is calculated directly on the subkey being revoked.\n"
  "A revoked subkey is not to be used.  Only revocation signatures\n"
  "by the top-level signature key that is bound to this subkey, or\n"
  "by an authorized revocation key, should be considered valid\n"
  "revocation signatures.\n"
}, {
  0x30, "Certification Revocation Signature",
  "This signature revokes an earlier User ID certification signature\n"
  "(signature class 0x10 through 0x13) or direct-key signature\n"
  "(0x1F).  It should be issued by the same key that issued the\n"
  "revoked signature or an authorized revocation key.  The signature\n"
  "is computed over the same data as the certificate that it\n"
  "revokes, and should have a later creation date than that\n"
  "certificate.\n"
}, {
  0x40, "Timestamp Signature",
  "This signature is only meaningful for the timestamp contained in\n"
  "it.\n"
}, {
  0x50, "Third-Party Confirmation Signature",
  "This signature is a signature over some other OpenPGP Signature\n"
  "packet(s).  It is analogous to a notary seal on the signed data.\n"
  "A third-party signature SHOULD include Signature Target\n"
  "subpacket(s) to give easy identification.  Note that we really do\n"
  "mean SHOULD.  There are plausible uses for this (such as a blind\n"
  "party that only sees the signature, not the key or source\n"
  "document) that cannot include a target subpacket.\n"
}, {
  /* sentinel */
  0xff, 0, 0
}};

static char *
find_type_string(ptpgp_signature_type_t t, char is_name) {
  size_t i;

  for (i = 0; types[i].name; i++)
    if (types[i].type == t)
      return is_name ? types[i].name : types[i].description;

  return NULL;
}

static ptpgp_err_t
find_type_and_copy(ptpgp_signature_type_t t, 
                   char is_name,
                   u8 *dst,
                   size_t dst_len,
                   size_t *out_len) {

  char *s = find_type_string(t, is_name);
  size_t l;

  if (!s)
    return PTPGP_ERR_SIGNATURE_TYPE_UNKNOWN_TYPE;

  /* get/check string length */
  l = strlen(s) + 1;
  if (l > dst_len)
    return PTPGP_ERR_SIGNATURE_TYPE_DEST_BUFFER_TOO_SMALL;

  /* copy string */
  memcpy(dst, s, l);

  if (out_len)
    *out_len = l;

  /* return success */
  return PTPGP_OK;
}

ptpgp_err_t
ptpgp_signature_type_to_s(ptpgp_signature_type_t t, 
                          u8 *dst,
                          size_t dst_len,
                          size_t *out_len) {
  return find_type_and_copy(t, 1, dst, dst_len, out_len);
}

ptpgp_err_t
ptpgp_signature_type_description(ptpgp_signature_type_t t, 
                                 u8 *dst,
                                 size_t dst_len,
                                 size_t *out_len) {
  return find_type_and_copy(t, 0, dst, dst_len, out_len);
}
