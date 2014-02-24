/*
 * uniformdh.c: Python UniformDH (OpenSSL based)
 *
 * This implements the Tor Project's UniformDH handshake as a Python module in
 * an attempt to provide a superior alternative to using gmpy.  The code is
 * based on the C++ implementation by the same author as part of the obfsclient
 * project.
 *
 * WARNING: While care is taken to sanitize variables containing sensitive
 * keying information to prevent forensics, in the grand scheme of things this
 * is belived by the author to be a lost cause due to the rest of the
 * cryptographic code and Python interpreter.
 */

/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define PY_SSIZE_T_CLEAN

#include "Python.h"

#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

/* The RFC 3526 1536-bit MODP Group ("Group 5") */
static const unsigned char rfc3526_group_5_p[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
  0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
  0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
  0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
  0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
  0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
  0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
  0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
  0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
  0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
  0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
  0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char rfc3526_group_5_g[] = {
  0x02
};

#define KEY_SIZE 192

/* You are in a maze of boilerplate, wondering why you didn't use SWIG */
typedef struct {
  PyObject_HEAD

  DH* ctx_;               /* OpenSSL DH context */
  PyObject* public_key_;  /* Public key */
} UniformDHObject;

static PyTypeObject UniformDH_Type;

static PyObject* generate_pub_key(UniformDHObject* self, int was_odd);

static int UniformDH_init(UniformDHObject*self, PyObject* args,
                          PyObject* kwargs);
static PyObject* UniformDH_get_public(UniformDHObject* self, PyObject* args);
static PyObject* UniformDH_get_secret(UniformDHObject* self, PyObject* args);
static void UniformDH_dealloc(UniformDHObject* self);

static PyMethodDef UniformDH_methods[] = {
  { "get_public", (PyCFunction)UniformDH_get_public, METH_NOARGS, "Return the public key as a 192 octet string" },
  { "get_secret", (PyCFunction)UniformDH_get_secret, METH_VARARGS, "Calculate the 192 octet shared secret" },
  { NULL, NULL }
};

static PyTypeObject UniformDH_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "UniformDH",              /* tp_name */
  sizeof(UniformDHObject),  /* tp_basicsize */
  0,                        /* tp_itemsize */
  /* methods */
  (destructor)UniformDH_dealloc,  /* tp_dealloc */
  0,                        /* tp_print */
  0,                        /* tp_getattr */
  0,                        /* tp_setattr */
  0,                        /* tp_compare */
  0,                        /* tp_repr */
  0,                        /* tp_as_number */
  0,                        /* tp_as_sequence */
  0,                        /* tp_as_mapping */
  0,                        /* tp_hash */
  0,                        /* tp_call */
  0,                        /* tp_str */
  0,                        /* tp_getattr */
  0,                        /* tp_setattr */
  0,                        /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  "UniformDH object",       /* tp_doc */
  0,                        /* tp_traverse */
  0,                        /* tp_clear */
  0,                        /* tp_richcompare */
  0,                        /* tp_weaklistoffset */
  0,                        /* tp_iter */
  0,                        /* tp_iternext */
  UniformDH_methods,        /* tp_methods */
  0,                        /* tp_members */
  0,                        /* tp_getset */
  0,                        /* tp_base */
  0,                        /* tp_dict */
  0,                        /* tp_descr_get */
  0,                        /* tp_descr_set */
  0,                        /* tp_dictoffset */
  (initproc)UniformDH_init, /* tp_init */
  0,                        /* tp_alloc */
  0,                        /* tp_new */
  0,                        /* tp_free */
  0,                        /* tp_is_gc */
};

PyMODINIT_FUNC
inituniformdh(void)
{
  PyObject* m = NULL;

  UniformDH_Type.tp_new = PyType_GenericNew;
  if (0 > PyType_Ready(&UniformDH_Type))
    return;

  m = Py_InitModule3("uniformdh", NULL, "OpenSSL based UniformDH");
  if (m == NULL)
    return;


  Py_INCREF(&UniformDH_Type);
  PyModule_AddObject(m, "UniformDH", (PyObject*)&UniformDH_Type);
}

static PyObject*
generate_pub_key(UniformDHObject* self, int was_odd)
{
  BIGNUM* p_sub_X = BN_new();
  PyObject* ret = NULL;

  if (p_sub_X == NULL)
    return ret;

  /* Always generate p - X, so that generation time is constant */
  if (1 == BN_sub(p_sub_X, self->ctx_->p, self->ctx_->pub_key)) {
    const BIGNUM* k = (was_odd) ? p_sub_X : self->ctx_->pub_key;
    unsigned char pub_key[KEY_SIZE] = { 0 };
    const size_t offset = sizeof(pub_key) - BN_num_bytes(k);

    int foo = BN_bn2bin(k, pub_key + offset);
    if (sizeof(pub_key) == offset + foo)
      ret = PyString_FromStringAndSize(pub_key, sizeof(pub_key));
  }

  BN_free(p_sub_X);
  return ret;
}

/* UniformDH.__init__(self, priv_key) */
static int 
UniformDH_init(UniformDHObject*self, PyObject* args, PyObject* kwargs)
{
  static char* kwlist[] = { "priv_key", NULL };
  PyObject* priv_key = NULL;
  int is_odd = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O:new", kwlist, &priv_key))
    return -1;
  if (priv_key != NULL) {
    if (!PyString_Check(priv_key)) {
      PyErr_SetString(PyExc_TypeError, "priv_key must be a string");
      return -1;
    }
    if (KEY_SIZE != PyString_Size(priv_key)) {
      PyErr_SetString(PyExc_ValueError, "priv_key must be 1536 bits");
      return -1;
    }
  }

  /* Initialize the DH context with p and g */
  self->ctx_ = DH_new();
  if (self->ctx_ == NULL) {
    PyErr_SetString(PyExc_MemoryError, "DH_new()");
    return -1;
  }
  self->ctx_->p = BN_bin2bn(rfc3526_group_5_p, sizeof(rfc3526_group_5_p), NULL);
  self->ctx_->g = BN_bin2bn(rfc3526_group_5_g, sizeof(rfc3526_group_5_g), NULL);
  if (self->ctx_->p == NULL || self->ctx_->g == NULL) {
    PyErr_SetString(PyExc_MemoryError, "BN_bin2bn() - p, g");
    return -1;
  }

  /* Generate the private key (or use the provided one) */
  if (priv_key == NULL) {
    /* Generate a random private key */
    self->ctx_->priv_key = BN_new();
    if (self->ctx_->priv_key == NULL) {
      PyErr_SetString(PyExc_MemoryError, "BN_new()");
      return -1;
    }
    if (1 != BN_rand(self->ctx_->priv_key, KEY_SIZE * 8, -1, 0)) {
      PyErr_SetString(PyExc_SystemError, "BN_rand()");
      return -1;
    }
  } else {
    /* Use the user supplied private key */
    self->ctx_->priv_key = BN_bin2bn(PyString_AsString(priv_key), 
                                     PyString_Size(priv_key),
                                     NULL);
    if (self->ctx_->priv_key == NULL)
      PyErr_SetString(PyExc_MemoryError, "BN_bin2bn() - priv_key");
      return -1;
  }

  /* Fix up the private key by forcing it to be odd */
  is_odd = BN_is_odd(self->ctx_->priv_key);
  if (1 != BN_clear_bit(self->ctx_->priv_key, 0)) {
    PyErr_SetString(PyExc_SystemError, "BN_clear_bit()");
    return -1;
  }

  /* Generate the public key */
  if (1 != DH_generate_key(self->ctx_)) {
    PyErr_SetString(PyExc_SystemError, "DH_generate_key()");
    return -1;
  }

  /* Generate the transmittable public key (X or p - X) */
  self->public_key_ = generate_pub_key(self, is_odd);
  if (self->public_key_ == NULL) {
    PyErr_SetString(PyExc_MemoryError, "generate_pub_key()");
    return -1;
  }

  return 0;

opessl_fail:
  PyErr_SetString(PyExc_SystemError, "OpenSSL math failure");
  return -1;
}

/* UniformDH.get_public(self) */
static PyObject*
UniformDH_get_public(UniformDHObject* self, PyObject* args)
{
  Py_INCREF(self->public_key_);
  return self->public_key_;
}

/* UniformDH.get_secret(self, their_pub_str) */
static PyObject*
UniformDH_get_secret(UniformDHObject* self, PyObject* args)
{
  PyObject* ret = NULL;
  unsigned char secret[KEY_SIZE];
  unsigned char* pub_key = NULL;
  Py_ssize_t len = 0;

  assert(DH_size(self->ctx_) == sizeof(secret));

  if (!PyArg_ParseTuple(args, "s#:get_secret", &pub_key, &len))
    return NULL;

  BIGNUM* peer_public_key = BN_bin2bn(pub_key, len, NULL);
  if (peer_public_key == NULL)
    return PyErr_NoMemory();

  /*
   * When a party wants to calculate the shared secret, she raises the foreign
   * public key to her private key. Note that both (p-Y)^x = Y^x (mod p) and
   * (p-X)^y = X^y (mod p), since x and y are even.
   *
   * Notes:
   *  * The spec says to just raise it, but the python code does Y^x (mod p)
   *  * Since OpenSSL doesn't have a routine for creating a DH shared secret
   *    that's a fixed size, this leaks some timing information when generating
   *    the return value.
   */

  int sz = DH_compute_key(secret, peer_public_key, self->ctx_);
  if (sz >= 0 && sz <= KEY_SIZE) {
    const int offset = sizeof(secret) - sz;
    if (offset > 0) {
      memmove(secret + offset, secret, sz);
      memset(secret, 0, offset);
    }
    ret = PyString_FromStringAndSize(secret, sizeof(secret));
  } else
    ret = PyExc_ValueError;

  OPENSSL_cleanse(secret, sizeof(secret));
  BN_free(peer_public_key);

  return ret;
}

/* UniformDH.__dealloc__(self) */
static void
UniformDH_dealloc(UniformDHObject* self)
{
  if (self->ctx_ != NULL)
    DH_free(self->ctx_);

  Py_XDECREF(self->public_key_);

  PyObject_Del(self);
}
