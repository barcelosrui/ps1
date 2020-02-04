#include "mbedtls/camellia.h";
#include "mbedtls/des.h"
#include "mbedtls/aes.h";
#include "mbedtls/md.h"
#include "mbedtls/chacha20.h"
#include "Crypto/Curve25519.h"
#include "mbedtls/poly1305.h"

#include "Crypto.h"
#include "Curve25519.h"
#include "RNG.h"
#include <string.h>

// iv, AES
// iv2, 3DES

//#########################################
// metodo de encriptação
#define ECB 1
#define CBC 2
#define CFB 3
#define CTR 4
#define OFB 5

//#########################################
// chaves para cifra simetrica
unsigned char key[16] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70}; //"abcdefghijklmnop";
char * key2 = "abcdefghijklmnopabcdefghijklmnop";
unsigned char key3[8] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68};

// ########################################
// Valores do IV para serem usados no
// b6589fc6ab0dc82cf12099d1c2d40ab9 = IV
unsigned char iv[16] = {0xb6, 0x58, 0x9f, 0xc6, 0xab, 0x0d, 0xc8, 0x2c, 0xf1, 0x20, 0x99, 0xd1, 0xc2, 0xd4, 0x0a, 0xb9};
unsigned char iv2[8] = {0xb6, 0x58, 0x9f, 0xc6, 0xab, 0x0d, 0xc8, 0x2c};

//#########################################
// "Temp: XX Hum: XX" em HEX
unsigned char texto16[16] = {0x54, 0x65, 0x6d, 0x70, 0x3a, 0x20, 0x58, 0x58, 0x20, 0x48, 0x75, 0x6d, 0x3a, 0x20, 0x58, 0x58};
unsigned char texto8[8] = {0x54, 0x65, 0x6d, 0x70, 0x3a, 0x20, 0x58, 0x58};

//#########################################
// TEXTO CIFRADO
unsigned char aesECB[16] = {0x15, 0x8c, 0xf2, 0x5d, 0xd7, 0x69, 0x4f, 0x58, 0x9c, 0x30, 0x67, 0x9f, 0x30, 0x24, 0x3a, 0xdb};
unsigned char aesCBC[16] = {0x2b, 0xe4, 0xba, 0x91, 0x88, 0x74, 0xd8, 0xff, 0xaa, 0xc2, 0xc, 0x66, 0x45, 0x1d, 0xd9, 0xec};
unsigned char aesCFB[16] = {0xa5, 0xaa, 0xd9, 0xdb, 0xe8, 0xb6, 0x8c, 0x67, 0xaf, 0x36, 0xdc, 0x8a, 0xe0, 0x8a, 0xef, 0x14};
unsigned char aesCTR[16] = {0xa5, 0xaa, 0xd9, 0xdb, 0xe8, 0xb6, 0x8c, 0x67, 0xaf, 0x36, 0xdc, 0x8a, 0xe0, 0x8a, 0xef, 0x14};
unsigned char aesOFB[16] = {0xa5, 0xaa, 0xd9, 0xdb, 0xe8, 0xb6, 0x8c, 0x67, 0xaf, 0x36, 0xdc, 0x8a, 0xe0, 0x8a, 0xef, 0x14};

unsigned char camelliaECB[16] = {0x20, 0x48, 0x75, 0x6d, 0x3a, 0x20, 0x58, 0x58, 0x54, 0x65, 0x6d, 0x70, 0x3a, 0x20, 0x58, 0x58};
unsigned char camelliaCBC[16] = {0xd1, 0x68, 0xec, 0xbc, 0xf8, 0xf4, 0x52, 0xe1, 0xe2, 0x3d, 0xf2, 0xb6, 0x91, 0x2d, 0x90, 0x74};
unsigned char camelliaCFB[16] = {0xa5, 0x45, 0xf4, 0xa1, 0xf8, 0xf4, 0x52, 0xe1, 0x96, 0x10, 0xea, 0xab, 0x91, 0x2d, 0x90, 0x74};
unsigned char camelliaCTR[16] = {0xa5, 0x45, 0xf4, 0xa1, 0xf8, 0xf4, 0x52, 0xe1, 0x96, 0x10, 0xea, 0xab, 0x91, 0x2d, 0x90, 0x74};

unsigned char DES3ECB[8] = {0x49, 0xc2, 0x99, 0xf4, 0xa3, 0xcb, 0x9a, 0x68};
unsigned char DES3CBC[8] = {0xf7, 0x94, 0xf2, 0xd3, 0xc2, 0x1, 0xba, 0x5a};

unsigned char DESECB[12] = {0x25, 0xad, 0x67, 0x18, 0x41, 0x85, 0xe8, 0xaf, 0x61, 0x21, 0xe1, 0x21};
unsigned char DESCBC[10] = {0x3d, 0x4c, 0xdf, 0xb8, 0x5d, 0x30, 0x22, 0xd7, 0x12, 0x30};

unsigned char chacha20txt[16] = {0xcb, 0xbe, 0x68, 0x91, 0x7a, 0x5d, 0x22, 0x6d, 0x2b, 0x2c, 0x7e, 0x97, 0x86, 0x3f, 0xc3, 0xd4};

static uint8_t alice_private[32] = {
  0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
  0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
  0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
  0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

static uint8_t const alice_public[32] = {
  0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
  0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
  0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
  0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};

static uint8_t bob_private[32] = {
  0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
  0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
  0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
  0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};

static uint8_t const bob_public[32] = {
  0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
  0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
  0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
  0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static uint8_t const shared_secret[32] = {
  0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
  0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
  0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
  0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
};

static uint8_t const crypted[32] =  {
  0x60, 0x2f, 0x2c, 0xf4, 0xad, 0xcf, 0x11, 0x8c,
  0x7c, 0x9f, 0x33, 0xb6, 0x11, 0xac, 0xc1, 0x20,
  0xeb, 0x13, 0x47, 0xa3, 0x35, 0x63, 0x98, 0x7d,
  0x79, 0xef, 0x74, 0x33, 0xb6, 0x9e, 0xd5, 0x4d  
};


void setup() {
  Serial.begin(9600);

  unsigned char cipherTextOutput[16];  // 8 carateres DES e 3DES // camellia 16 // AES 16
  unsigned char cipherTextOutput8[8];  // 8 carateres DES e 3DES // camellia 16 // AES 16

  unsigned char * cipherTextInput = texto16; // {0x54, 0x65, 0x6d, 0x70, 0x3a, 0x20, 0x58, 0x58, 0x20, 0x48, 0x75, 0x6d, 0x3a, 0x20, 0x58, 0x58};  // 8 carateres DES e 3DES
  unsigned char * cipherTextInput8 = texto8;// {0x54, 0x65, 0x6d, 0x70, 0x3a, 0x20, 0x58, 0x58};  // 8 carateres DES e 3DES

  //##################################################################
  TCCR3A = 0;   // CONTADOR
  TCCR3B = 0;
  TCNT3 = 0;
  TCCR3B |= (1 << CS12);

  //encryptAES(cipherTextInput, key, cipherTextOutput, OFB);
  //decryptAES(aesECB, key, cipherTextInput2, ECB);

  //encryptcam(cipherTextInput, key, cipherTextOutput, ECB);
  //decryptcam(camelliaCTR, key, cipherTextInput2, CTR);

  //encrypt3DES(cipherTextInput8, key, cipherTextOutput8, CBC);
  //decrypt3DES(DES3ECB, key, cipherTextOutput8, ECB);

  //encryptDES(cipherTextInput8, key3, cipherTextOutput8, CBC);
  //decryptDES(DESCBC, key3, cipherTextOutput8, CBC);

  //byte hmacResult[32]; // hmac
  //hmac(cipherTextInput, key, hmacResult ); // hmac

  /*mbedtls_md_type_t md_type = MBEDTLS_MD_MD5; //MBEDTLS_MD_SHA256;
    byte hashResult[16]; // md5/sha1 16 // sha256 = 32 // sha512 = 64
    hash(cipherTextInput, hashResult, md_type);*/

  /*char *nonce = "sLKmAKjEmMU=";
    encryptchacha20(chacha20txt, key2, cipherTextOutput, nonce);*/

  //poly1305( cipherTextOutput, key, cipherTextOutput );
  //curves();
  
  //                 contador * 1/16mhz * prescalar
  unsigned long tmp = (TCNT3) * 0.0625 * 256;

  //##################################################################

  //mostrarcifra(cipherTextOutput);
  ///Serial.println("");
  //mostrarcifraV2(cipherTextOutput);
  //mostrartexto(cipherTextOutput);

  Serial.println("");
  Serial.println(tmp);
}

void mostrartexto(unsigned char *cipherTextInput) {
  // mostrar texto
  for (int i = 0; i < strlen(cipherTextInput); i++) { // converter o numero hexadecimal para string
    Serial.print( (char) cipherTextInput[i] );
  }
}

void mostrarcifra(unsigned char * cipherTextOutput) {
  // mostrar cifra
  Serial.print("{");
  for (int i = 0; i < strlen(cipherTextOutput); i++) { // converter o numero hexadecimal para string
    char str[3];
    //sprintf(str, "%02x", (int)cipherTextOutput[i]); // mostrar em HEX
    sprintf(str, "0x%x", (int)cipherTextOutput[i]);

    Serial.print(str);
    if (i < strlen(cipherTextOutput) - 1) Serial.print(", ");
  }
  Serial.print("}");
}

void mostrarcifraV2(unsigned char * cipherTextOutput) {
  // mostrar cifra HEX

  for (int i = 0; i < 16; i++) { // converter o numero hexadecimal para string
    char str[3];
    sprintf(str, "%02x", (int)cipherTextOutput[i]); // mostrar em HEX

    Serial.print(str);
  }
}

void printNumber(const char *name, const uint8_t *x)
{
  static const char hexchars[] = "0123456789ABCDEF";
  Serial.print(name);
  Serial.print(" = ");
  for (uint8_t posn = 0; posn < 32; ++posn) {
    Serial.print(hexchars[(x[posn] >> 4) & 0x0F]);
    Serial.print(hexchars[x[posn] & 0x0F]);
  }
  Serial.println();
}

void curves() {

  alice_private[0] &= 0xF8;
  alice_private[31] = (alice_private[31] & 0x7F) | 0x40;

  bob_private[0] &= 0xF8;
  bob_private[31] = (bob_private[31] & 0x7F) | 0x40;

  uint8_t result[32];

  //Curve25519::eval(result, alice_private, 0); // verificar se as chaves publicas são iguais á acima
  //Curve25519::eval(result, bob_private, 0); // verificar se as chaves publicas são iguais á acima

  //Curve25519::eval(result, alice_private, bob_public); // cifra publica do bob

  //Curve25519::eval(result, bob_private, alice_public);

  static uint8_t alice_k[32];
  static uint8_t alice_f[32];
  static uint8_t bob_k[32];
  static uint8_t bob_f[32];

  Curve25519::dh1(alice_k, alice_f);
  Curve25519::dh1(bob_k, bob_f);

  //Curve25519::dh2(bob_k, alice_f);
  //Curve25519::dh2(alice_k, bob_f);
  
  mostrarcifra(bob_f);

}

void poly1305(unsigned char key, unsigned char *input, unsigned char * outputBuffer) {

  mbedtls_poly1305_context poly;
  mbedtls_poly1305_init(&poly);
  mbedtls_poly1305_starts(&poly, key);
  mbedtls_poly1305_mac( key, input, strlen(input), outputBuffer);
  mbedtls_poly1305_free(&poly);

}

void encryptchacha20(const char * plainText, char * key, unsigned char * outputBuffer, char * nonce) {

  mbedtls_chacha20_context cha;
  int i = 0;
  mbedtls_chacha20_init( &cha );
  mbedtls_chacha20_setkey( &cha, (const unsigned char*) key);
  mbedtls_chacha20_starts(&cha, (const unsigned char*)"sLKmAKjEmMU=", i);
  mbedtls_chacha20_crypt((const unsigned char*) key , (const unsigned char*) nonce , i, sizeof(plainText) * 8 , (const unsigned char*)plainText  , (unsigned char*)outputBuffer );
  mbedtls_chacha20_free( &cha );
}

void hmac(char *payload, unsigned char *chave, byte *hmacResult) {

  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  const size_t payloadLength = strlen(payload);
  const size_t keyLength = strlen(chave);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) chave, keyLength);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *) payload, payloadLength);
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);
}

void hash(char *payload, byte *shaResult, mbedtls_md_type_t md_type) {

  mbedtls_md_context_t ctx;

  const size_t payloadLength = strlen(payload);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *) payload, payloadLength);
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);
}

void encryptcam(char * plainText, char * key, unsigned char * outputBuffer, int metodo) {

  mbedtls_camellia_context bl;

  mbedtls_camellia_init( &bl );
  mbedtls_camellia_setkey_enc( &bl, (const unsigned char*) key, strlen(key) * 8 );

  switch (metodo) {
    case 1:
      mbedtls_camellia_crypt_ecb( &bl, MBEDTLS_CAMELLIA_ENCRYPT, (const unsigned char*)plainText, outputBuffer);
      break;
    case 2:
      mbedtls_camellia_crypt_cbc( &bl, MBEDTLS_CAMELLIA_ENCRYPT, 16, iv , (const unsigned char*)plainText, outputBuffer);
      break;
    case 3:
      mbedtls_camellia_crypt_cfb128( &bl, MBEDTLS_CAMELLIA_ENCRYPT, strlen(plainText), 0, iv , (const unsigned char*)plainText, outputBuffer);
      break;
    case 4:
      mbedtls_camellia_crypt_ctr(&bl, strlen(plainText), 0, iv, 0, (const unsigned char*)plainText, outputBuffer);
      break;
  }
  mbedtls_camellia_free( &bl );

}

void decryptcam(unsigned char * inputBuffer, char * key, unsigned char * outputBuffer, int metodo) {

  mbedtls_camellia_context bl;
  mbedtls_camellia_init( &bl );
  mbedtls_camellia_setkey_dec( &bl, (const unsigned char*) key, strlen(key) * 8 );
  switch (metodo) {
    case 1:
      mbedtls_camellia_crypt_ecb( &bl, MBEDTLS_CAMELLIA_DECRYPT, (const unsigned char*)inputBuffer , outputBuffer);
      break;
    case 2:
      mbedtls_camellia_crypt_cbc( &bl, MBEDTLS_CAMELLIA_DECRYPT, 16, iv , (const unsigned char*)inputBuffer, outputBuffer);
      break;
    case 3:
      mbedtls_camellia_crypt_cfb128( &bl, MBEDTLS_CAMELLIA_DECRYPT, strlen(inputBuffer), 0, iv , (const unsigned char*)inputBuffer, outputBuffer);
      break;
    case 4:
      mbedtls_camellia_crypt_ctr(&bl, strlen(inputBuffer), 0, iv, 0, (const unsigned char*)inputBuffer, outputBuffer);
      break;

  }

  mbedtls_camellia_free( &bl );
}

void encrypt3DES(char * plainText, char * key, char * outputBuffer, int metodo) {

  mbedtls_des3_context des;

  mbedtls_des3_init( &des );
  mbedtls_des3_set2key_enc( &des, (const unsigned char*) key);

  switch (metodo) {
    case 1:
      mbedtls_des3_crypt_ecb( &des, (const unsigned char*)plainText, outputBuffer);
      break;
    case 2:
      mbedtls_des3_crypt_cbc( &des, MBEDTLS_DES_ENCRYPT , 8, iv2, (const unsigned char*)plainText, outputBuffer);
      break;
  }

  mbedtls_des3_free( &des );
}

void decrypt3DES(char * plainText, unsigned char * key, unsigned char * outputBuffer, int metodo) {

  mbedtls_des3_context des;

  mbedtls_des3_init( &des );
  mbedtls_des3_set2key_dec( &des, key);

  switch (metodo) {
    case 1:
      mbedtls_des3_crypt_ecb( &des, (const unsigned char*)plainText, outputBuffer);
      break;
    case 2:
      mbedtls_des3_crypt_cbc( &des, MBEDTLS_DES_DECRYPT , 8, iv2, (const unsigned char*)plainText, outputBuffer);
      break;
  }

  mbedtls_des3_free( &des );
}

void encryptDES(char * plainText, char * key, unsigned char * outputBuffer, int metodo) {

  mbedtls_des_context des;

  mbedtls_des_init( &des );
  mbedtls_des_setkey_enc( &des, (const unsigned char*) key);
  switch (metodo) {
    case 1:
      mbedtls_des_crypt_ecb( &des, (const unsigned char*)plainText, outputBuffer);
      break;
    case 2:
      mbedtls_des_crypt_cbc( &des, MBEDTLS_DES_ENCRYPT , 8, iv2, (const unsigned char*) plainText, outputBuffer);
      break;
  }
  mbedtls_des_free( &des );

}

void decryptDES(unsigned char * chipherText, char * key, unsigned char * outputBuffer, int metodo) {

  mbedtls_des_context des;

  mbedtls_des_init( &des );
  mbedtls_des_setkey_dec( &des, (const unsigned char*) key3);
  switch (metodo) {
    case 1:
      mbedtls_des_crypt_ecb(&des, (const unsigned char*)chipherText, outputBuffer);
      break;
    case 2:
      mbedtls_des_crypt_cbc( &des, MBEDTLS_DES_DECRYPT, 8, iv2, (const unsigned char*) chipherText, outputBuffer);
      break;
  }
  mbedtls_des_free( &des );
}

void encryptAES(char * plainText, char * key, unsigned char * outputBuffer, int metodo) {

  mbedtls_aes_context aes;

  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_enc( &aes, key, 128/*strlen(key)*/ );
  switch (metodo) {
    case 1:
      mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plainText, outputBuffer);
      break;
    case 2:
      mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, strlen(iv), iv, plainText, outputBuffer);
      break;
    case 3:
      mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, strlen(plainText), 0, iv, (const unsigned char*)plainText, outputBuffer);
      break;
    case 4:
      mbedtls_aes_crypt_ctr(&aes, strlen(plainText), 0, iv, 0, (const unsigned char*)plainText, outputBuffer);
      break;
    case 5:
      mbedtls_aes_crypt_ofb( &aes, strlen(plainText), 0, iv, plainText, outputBuffer );
      break;
  }
  mbedtls_aes_free( &aes );
}

void decryptAES(unsigned char * chipherText, unsigned char * key, unsigned char * outputBuffer, int metodo) {

  mbedtls_aes_context aes;

  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_dec( &aes, key, 128 );

  switch (metodo) {
    case 1:
      mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char*)chipherText, outputBuffer);
      break;
    case 2:
      mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, strlen(iv), iv, (const unsigned char*)chipherText, outputBuffer);
      break;
    case 3:
      mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, strlen(iv) , 0, iv, (const unsigned char*)chipherText, outputBuffer);
      break;
    case 4:
      mbedtls_aes_crypt_ctr(&aes, strlen(chipherText), 0, iv, 0, (const unsigned char*)chipherText, outputBuffer);
      break;
    case 5:
      mbedtls_aes_crypt_ofb( &aes, strlen(chipherText), 0, iv, chipherText, outputBuffer );
  }
  mbedtls_aes_free( &aes );
}

void loop() {
}
