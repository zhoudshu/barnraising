/* ssl/i1_both.c */

#include "ssl_locl.h"


int imp1_send_key_expose(SSL *s, int a, int b)
{ 
  if (s->state == a) {
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int key_length, iv_length;
    char *p = (unsigned char*) s->init_buf->data;

    s->method->ssl3_enc->compute_cipher_state( s,
         SSL3_CHANGE_CIPHER_SERVER_WRITE,
         NULL, NULL,
         key, &key_length,
         iv, &iv_length );

    *p++ = key_length & 0xFF;
    memcpy( p, key, key_length );
    p += key_length;
    *p++ = iv_length & 0xFF;
    memcpy( p, iv, iv_length );

    s->init_num = 2 + key_length + iv_length;
    s->init_off = 0;

    s->state = b;
  }

  return ssl3_do_write( s, IMP1_RT_KEY_EXPOSE );
}
