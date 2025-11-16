/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sec/rng.h>

#include "py/objstr.h"

#include "vendor/trezor-crypto/bignum.h"
#include "vendor/trezor-crypto/ecdsa.h"
#include "vendor/trezor-crypto/secp256k1.h"

/// package: trezorcrypto.secp256k1

/// def generate_secret() -> bytes:
///     """
///     Generate secret key.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_generate_secret() {
  vstr_t sk = {0};
  vstr_init_len(&sk, 32);
  for (;;) {
    rng_fill_buffer((uint8_t *)sk.buf, sk.len);
    // check whether secret > 0 && secret < curve_order
    if (0 ==
        memcmp(
            sk.buf,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            32))
      continue;
    if (0 <=
        memcmp(
            sk.buf,
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE"
            "\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41",
            32))
      continue;
    break;
  }
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &sk);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(mod_trezorcrypto_secp256k1_generate_secret_obj,
                                 mod_trezorcrypto_secp256k1_generate_secret);

/// def publickey(secret_key: AnyBytes, compressed: bool = True) -> bytes:
///     """
///     Computes public key from secret key.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_publickey(size_t n_args,
                                                     const mp_obj_t *args) {
  mp_buffer_info_t sk = {0};
  mp_get_buffer_raise(args[0], &sk, MP_BUFFER_READ);
  if (sk.len != 32) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of secret key"));
  }
  vstr_t pk = {0};
  int ret = 0;
  bool compressed = n_args < 2 || args[1] == mp_const_true;
  if (compressed) {
    vstr_init_len(&pk, 33);
    ret = ecdsa_get_public_key33(&secp256k1, (const uint8_t *)sk.buf,
                                 (uint8_t *)pk.buf);
  } else {
    vstr_init_len(&pk, 65);
    ret = ecdsa_get_public_key65(&secp256k1, (const uint8_t *)sk.buf,
                                 (uint8_t *)pk.buf);
  }
  if (0 != ret) {
    vstr_clear(&pk);
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid secret key"));
  }
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pk);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_publickey_obj, 1, 2,
    mod_trezorcrypto_secp256k1_publickey);

#if !BITCOIN_ONLY

static int ethereum_is_canonical(uint8_t v, uint8_t signature[64]) {
  (void)signature;
  return (v & 2) == 0;
}

static int eos_is_canonical(uint8_t v, uint8_t signature[64]) {
  (void)v;
  return !(signature[0] & 0x80) &&
         !(signature[0] == 0 && !(signature[1] & 0x80)) &&
         !(signature[32] & 0x80) &&
         !(signature[32] == 0 && !(signature[33] & 0x80));
}

/// mock:global

/// CANONICAL_SIG_ETHEREUM: int = 1
/// CANONICAL_SIG_EOS: int = 2
enum {
  CANONICAL_SIG_ETHEREUM = 1,
  CANONICAL_SIG_EOS = 2,
};

#endif

/// def sign(
///     secret_key: AnyBytes,
///     digest: AnyBytes,
///     compressed: bool = True,
///     canonical: int | None = None,
/// ) -> bytes:
///     """
///     Uses secret key to produce the signature of the digest.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_sign(size_t n_args,
                                                const mp_obj_t *args) {
  mp_buffer_info_t sk = {0};
  mp_buffer_info_t dig = {0};
  mp_get_buffer_raise(args[0], &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(args[1], &dig, MP_BUFFER_READ);
  bool compressed = (n_args < 3) || (args[2] == mp_const_true);
  int (*is_canonical)(uint8_t by, uint8_t sig[64]) = NULL;
#if !BITCOIN_ONLY
  mp_int_t canonical = (n_args > 3) ? mp_obj_get_int(args[3]) : 0;
  switch (canonical) {
    case CANONICAL_SIG_ETHEREUM:
      is_canonical = ethereum_is_canonical;
      break;
    case CANONICAL_SIG_EOS:
      is_canonical = eos_is_canonical;
      break;
  }
#endif
  if (sk.len != 32) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of secret key"));
  }
  if (dig.len != 32) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of digest"));
  }
  vstr_t sig = {0};
  vstr_init_len(&sig, 65);
  uint8_t pby = 0;
  if (0 != ecdsa_sign_digest(&secp256k1, (const uint8_t *)sk.buf,
                             (const uint8_t *)dig.buf, (uint8_t *)sig.buf + 1,
                             &pby, is_canonical)) {
    vstr_clear(&sig);
    mp_raise_ValueError(MP_ERROR_TEXT("Signing failed"));
  }
  sig.buf[0] = 27 + pby + compressed * 4;
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &sig);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_secp256k1_sign_obj,
                                           2, 4,
                                           mod_trezorcrypto_secp256k1_sign);

/// def verify(
///     public_key: AnyBytes, signature: AnyBytes, digest: AnyBytes
/// ) -> bool:
///     """
///     Uses public key to verify the signature of the digest.
///     Returns True on success.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_verify(mp_obj_t public_key,
                                                  mp_obj_t signature,
                                                  mp_obj_t digest) {
  mp_buffer_info_t pk = {0}, sig = {0}, dig = {0};
  mp_get_buffer_raise(public_key, &pk, MP_BUFFER_READ);
  mp_get_buffer_raise(signature, &sig, MP_BUFFER_READ);
  mp_get_buffer_raise(digest, &dig, MP_BUFFER_READ);
  if (pk.len != 33 && pk.len != 65) {
    return mp_const_false;
  }
  if (sig.len != 64 && sig.len != 65) {
    return mp_const_false;
  }
  int offset = sig.len - 64;
  if (dig.len != 32) {
    return mp_const_false;
  }
  int ret = ecdsa_verify_digest(&secp256k1, (const uint8_t *)pk.buf,
                                (const uint8_t *)sig.buf + offset,
                                (const uint8_t *)dig.buf);
  return mp_obj_new_bool(ret == 0);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_secp256k1_verify_obj,
                                 mod_trezorcrypto_secp256k1_verify);

/// def verify_recover(signature: AnyBytes, digest: AnyBytes) -> bytes:
///     """
///     Uses signature of the digest to verify the digest and recover the public
///     key. Returns public key on success, None if the signature is invalid.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_verify_recover(mp_obj_t signature,
                                                          mp_obj_t digest) {
  mp_buffer_info_t sig = {0}, dig = {0};
  mp_get_buffer_raise(signature, &sig, MP_BUFFER_READ);
  mp_get_buffer_raise(digest, &dig, MP_BUFFER_READ);
  if (sig.len != 65) {
    return mp_const_none;
  }
  if (dig.len != 32) {
    return mp_const_none;
  }
  uint8_t recid = ((const uint8_t *)sig.buf)[0] - 27;
  if (recid >= 8) {
    return mp_const_none;
  }
  bool compressed = (recid >= 4);
  recid &= 3;
  vstr_t pk = {0};
  vstr_init_len(&pk, 65);
  if (ecdsa_recover_pub_from_sig(&secp256k1, (uint8_t *)pk.buf,
                                 (const uint8_t *)sig.buf + 1,
                                 (const uint8_t *)dig.buf, recid) == 0) {
    if (compressed) {
      pk.buf[0] = 0x02 | (pk.buf[64] & 1);
      pk.len = 33;
    }
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &pk);
  } else {
    return mp_const_none;
  }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_secp256k1_verify_recover_obj,
                                 mod_trezorcrypto_secp256k1_verify_recover);

/// def multiply(secret_key: AnyBytes, public_key: AnyBytes) -> bytes:
///     """
///     Multiplies point defined by public_key with scalar defined by
///     secret_key. Useful for ECDH.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_multiply(mp_obj_t secret_key,
                                                    mp_obj_t public_key) {
  mp_buffer_info_t sk = {0}, pk = {0};
  mp_get_buffer_raise(secret_key, &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(public_key, &pk, MP_BUFFER_READ);
  if (sk.len != 32) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of secret key"));
  }
  if (pk.len != 33 && pk.len != 65) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of public key"));
  }
  vstr_t out = {0};
  vstr_init_len(&out, 65);
  if (0 != ecdh_multiply(&secp256k1, (const uint8_t *)sk.buf,
                         (const uint8_t *)pk.buf, (uint8_t *)out.buf)) {
    vstr_clear(&out);
    mp_raise_ValueError(MP_ERROR_TEXT("Multiply failed"));
  }
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_secp256k1_multiply_obj,
                                 mod_trezorcrypto_secp256k1_multiply);

/// def scalar_add(s1: AnyBytes, s2: AnyBytes) -> bytes:
///     """
///     Adds 2 scalar values defined by s1 and s2.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_scalar_add(mp_obj_t s1, mp_obj_t s2) {
  mp_buffer_info_t sk1 = {0}, sk2 = {0};
  mp_get_buffer_raise(s1, &sk1, MP_BUFFER_READ);
  mp_get_buffer_raise(s2, &sk2, MP_BUFFER_READ);
  if (sk1.len != 32 || sk2.len != 32) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length"));
  }
  bignum256 k1 = {0}, k2 = {0};
  bn_read_be(sk1.buf, &k1);
  bn_read_be(sk2.buf, &k2);

  bn_addmod(&k1, &k2, &secp256k1.order);

  vstr_t out = {0};
  vstr_init_len(&out, 32);
  bn_write_be(&k1, (uint8_t *)out.buf);
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_secp256k1_scalar_add_obj,
                                 mod_trezorcrypto_secp256k1_scalar_add);

/// def scalar_multiply(s1: AnyBytes, s2: AnyBytes) -> bytes:
///     """
///     Multiplies 2 scalar values defined by s1 and s2.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_scalar_multiply(mp_obj_t s1, mp_obj_t s2) {
  mp_buffer_info_t sk1 = {0}, sk2 = {0};
  mp_get_buffer_raise(s1, &sk1, MP_BUFFER_READ);
  mp_get_buffer_raise(s2, &sk2, MP_BUFFER_READ);
  if (sk1.len != 32 || sk2.len != 32) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length"));
  }
  bignum256 k1 = {0}, k2 = {0};
  bn_read_be(sk1.buf, &k1);
  bn_read_be(sk2.buf, &k2);

  bn_multiply(&k1, &k2, &secp256k1.order);

  vstr_t out = {0};
  vstr_init_len(&out, 32);
  bn_write_be(&k2, (uint8_t *)out.buf);
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_secp256k1_scalar_multiply_obj,
                                 mod_trezorcrypto_secp256k1_scalar_multiply);

STATIC const mp_rom_map_elem_t mod_trezorcrypto_secp256k1_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1)},
    {MP_ROM_QSTR(MP_QSTR_generate_secret),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_generate_secret_obj)},
    {MP_ROM_QSTR(MP_QSTR_publickey),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_publickey_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_sign_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify_recover),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_verify_recover_obj)},
    {MP_ROM_QSTR(MP_QSTR_multiply),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_multiply_obj)},
    {MP_ROM_QSTR(MP_QSTR_scalar_add),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_scalar_add_obj)},
    {MP_ROM_QSTR(MP_QSTR_scalar_multiply),
     MP_ROM_PTR(&mod_trezorcrypto_secp256k1_scalar_multiply_obj)},
#if !BITCOIN_ONLY
    {MP_ROM_QSTR(MP_QSTR_CANONICAL_SIG_ETHEREUM),
     MP_ROM_INT(CANONICAL_SIG_ETHEREUM)},
    {MP_ROM_QSTR(MP_QSTR_CANONICAL_SIG_EOS), MP_ROM_INT(CANONICAL_SIG_EOS)},
#endif
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_secp256k1_globals,
                            mod_trezorcrypto_secp256k1_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_secp256k1_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezorcrypto_secp256k1_globals,
};
