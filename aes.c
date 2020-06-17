
// hardware accelerated 128 bit aes for any python version
// by rvcgeeks (Rajas Chavadekar) cybersecurity domain
// <github.com/rvcgeeks> <linkedin.com/in/rvchavadekar>
// some code of my propreitary RVCvault exposed into public domain for python under MIT licence attached 

// compile by     cc aes.c -march=native -fPIC $(python-config --includes) -shared -o aes.so   
// and run        python test.py

// tell python that PyArg_ParseTuple(t#) means Py_ssize_t, not int 

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
  typedef int Py_ssize_t;
#endif

// This is required for compatibility with Python 2

#if PY_MAJOR_VERSION >= 3
  #include <bytesobject.h> 
  #define y "y"
#else
  #define PyBytes_FromStringAndSize PyString_FromStringAndSize
  #define y "t"
#endif
    
#include <wmmintrin.h>  //for intrinsics for AES-NI
    
#define AES_SIZE 16 //16 bytes == 128 bits by default
#define K_SCH_SZ 20 //key schedule size .. 20 bytes for 128 bit aes
    
// 10 AES round en/decryption.
// core macros for en/decryption .. these are compiled down directly to AES NI CPU instructions 
// no looping .. as extra math for incrementing counter and jumping causes more cache hits .. lowers speed .. dont want that
  
#define AES_ENCRYPT_STUB(m, k)    \
  m = _mm_xor_si128(m, k[ 0]);    \
  m = _mm_aesenc_si128(m, k[ 1]); \
  m = _mm_aesenc_si128(m, k[ 2]); \
  m = _mm_aesenc_si128(m, k[ 3]); \
  m = _mm_aesenc_si128(m, k[ 4]); \
  m = _mm_aesenc_si128(m, k[ 5]); \
  m = _mm_aesenc_si128(m, k[ 6]); \
  m = _mm_aesenc_si128(m, k[ 7]); \
  m = _mm_aesenc_si128(m, k[ 8]); \
  m = _mm_aesenc_si128(m, k[ 9]); \
  m = _mm_aesenclast_si128(m, k[10]);

#define AES_DECRYPT_STUB(m, k)    \
  m = _mm_xor_si128(m, k[10]);    \
  m = _mm_aesdec_si128(m, k[11]); \
  m = _mm_aesdec_si128(m, k[12]); \
  m = _mm_aesdec_si128(m, k[13]); \
  m = _mm_aesdec_si128(m, k[14]); \
  m = _mm_aesdec_si128(m, k[15]); \
  m = _mm_aesdec_si128(m, k[16]); \
  m = _mm_aesdec_si128(m, k[17]); \
  m = _mm_aesdec_si128(m, k[18]); \
  m = _mm_aesdec_si128(m, k[19]); \
  m = _mm_aesdeclast_si128(m, k[ 0]);

#define AES_KEY_EXP_STUB(k, rcon) \
  key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
    
static __m128i key_expansion(__m128i key, __m128i keygened) {
    
  keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}

static void load_key_enc_only(uint8_t *key, __m128i *key_schedule) {
    
  key_schedule[ 0] = _mm_loadu_si128((const __m128i*) key);
  key_schedule[ 1] = AES_KEY_EXP_STUB(key_schedule[0], 0x01);
  key_schedule[ 2] = AES_KEY_EXP_STUB(key_schedule[1], 0x02);
  key_schedule[ 3] = AES_KEY_EXP_STUB(key_schedule[2], 0x04);
  key_schedule[ 4] = AES_KEY_EXP_STUB(key_schedule[3], 0x08);
  key_schedule[ 5] = AES_KEY_EXP_STUB(key_schedule[4], 0x10);
  key_schedule[ 6] = AES_KEY_EXP_STUB(key_schedule[5], 0x20);
  key_schedule[ 7] = AES_KEY_EXP_STUB(key_schedule[6], 0x40);
  key_schedule[ 8] = AES_KEY_EXP_STUB(key_schedule[7], 0x80);
  key_schedule[ 9] = AES_KEY_EXP_STUB(key_schedule[8], 0x1B);
  key_schedule[10] = AES_KEY_EXP_STUB(key_schedule[9], 0x36);
}

static void load_key(uint8_t *key, __m128i *key_schedule) {
    
  load_key_enc_only(key, key_schedule);
  key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);        // generate decryption keys in reverse order.
  key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);        // k[10] is shared by last encryption and first decryption rounds
  key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);        // k[0] is shared by first encryption round and last decryption round (and is the original user key)
  key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);        // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
  key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
  key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
  key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
  key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
  key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

//methods for block encryption

static void block_encrypt(uint8_t *cipherText, uint8_t *plainText, __m128i *key_schedule) {

  __m128i m = _mm_loadu_si128((__m128i *)plainText);
  AES_ENCRYPT_STUB(m, key_schedule);
  _mm_storeu_si128((__m128i *)cipherText, m);
}

static void block_decrypt(uint8_t *plainText, uint8_t *cipherText, __m128i *key_schedule) {
    
  __m128i m = _mm_loadu_si128((__m128i *)cipherText);
  AES_DECRYPT_STUB(m, key_schedule);
  _mm_storeu_si128((__m128i *)plainText, m);
}

// API methods for string encryption 

static PyObject *encrypt(PyObject *self, PyObject *args) {
  
  uint8_t *key, *in;
  Py_ssize_t i, keylen, txtlen;

  if(!PyArg_ParseTuple(args, y"#"y"#", &key, &keylen, &in, &txtlen)) {
    return NULL;
  }
  if (keylen < AES_SIZE) { // pad key to 16 bytes
    uint8_t *newkey = malloc(AES_SIZE);
    memset(newkey, 0, AES_SIZE);
    memcpy(newkey, key, AES_SIZE);
    key = newkey;
  }
  if (txtlen % AES_SIZE != 0) { // resize the input string to 16 byte multiple if not and pad it with zeros
    uint8_t newtxtlen = (txtlen / AES_SIZE + 1) * AES_SIZE;
    uint8_t *newin = malloc(newtxtlen);
    memset(newin, 0, newtxtlen);
    memcpy(newin, in, txtlen);
    in = newin;
    txtlen = newtxtlen;
  }
  
  __m128i key_schedule[K_SCH_SZ]; 
  load_key(key, key_schedule);
  
  uint8_t *out = malloc(txtlen);
  
  for(i = 0; i < txtlen; i += AES_SIZE) 
    block_encrypt(out + i, in + i, key_schedule);
  
  return PyBytes_FromStringAndSize(out, txtlen);
}

static PyObject *decrypt(PyObject *self, PyObject *args) {
  
  uint8_t *key, *in;
  Py_ssize_t i, keylen, txtlen;

  if(!PyArg_ParseTuple(args, y"#"y"#", &key, &keylen, &in, &txtlen)) {
    return NULL;
  }
  if (keylen < AES_SIZE) { // pad key to 16 bytes
    uint8_t *newkey = malloc(AES_SIZE);
    memset(newkey, 0, AES_SIZE);
    memcpy(newkey, key, AES_SIZE);
    key = newkey;
  }
  if (txtlen % AES_SIZE != 0) { // cuz its decryption, exact 16 byte multiple required ... hence throw error if not
    PyErr_SetString(PyExc_ValueError, "ciphertext must be 16-byte-multiple string");
    return NULL;
  }
  
  __m128i key_schedule[K_SCH_SZ]; 
  load_key(key, key_schedule);
  
  uint8_t *out = malloc(txtlen);
  
  for(i = 0; i < txtlen; i += AES_SIZE) 
    block_decrypt(out + i, in + i, key_schedule);
  
  return PyBytes_FromStringAndSize(out, txtlen);
}

#include <cpuid.h>

static PyObject *check(PyObject *self, PyObject *args) {
  
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
  __get_cpuid(1, &eax, &ebx, &ecx, &edx);
  if((ecx & bit_AES) > 0)
    return Py_True;
  else
    return Py_False;
}

// building the aes_module

static PyMethodDef aesMethods[] = {
  {"encrypt", (PyCFunction)encrypt, METH_VARARGS},
  {"decrypt", (PyCFunction)decrypt, METH_VARARGS},
  {"check", (PyCFunction)check, METH_VARARGS},
  {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef aes_module = {
  PyModuleDef_HEAD_INIT,
  "aes",
  NULL,
  (long int)NULL,
  aesMethods,
};

PyObject *PyInit_aes(void) {
  return PyModule_Create(&aes_module);
}
#else
PyMODINIT_FUNC initaes(void) {
  Py_InitModule("aes", aesMethods);
}
#endif
