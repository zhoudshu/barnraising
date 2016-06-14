/* ssl/i1_pkt.c */

#include "ssl_locl.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int params_inited = 0;
static char *shared_data_directory;
static int default_encoding;

#define IMP1_ENCODING_NULL       0x0001
#define IMP1_ENCODING_SEQ        0x0002
#define IMP1_ENCODING_HASH       0x0003




void
imp1_init_params()
{
  default_encoding = getenv( "IMP1_ENCODING" ) ?
    atoi( getenv( "IMP1_ENCODING" ) ) : IMP1_ENCODING_NULL;
  shared_data_directory =
    getenv( "IMP1_SHARED_DATA_DIRECTORY" ) ?
    getenv( "IMP1_SHARED_DATA_DIRECTORY" ) : "/var/cache/imptls";
}


int
imp1_choose_encoding(unsigned char *payload, int payload_len,
                     int record_type,
                     int ssl_version)
{
#if 0
  printf("imp1_choose_encoding( %i...[%i], %i, %i )\n",
         (int)payload[0], payload_len,
         record_type, ssl_version);
#endif

  if ( record_type == SSL3_RT_APPLICATION_DATA ) {
    /* XXX CTL we really should derive the break-even point dynamically,
       but this is roughly OK as long as we don't change the encoding. */
    if ( payload_len > 20 /* constant size of hash */ ) {
      /* Don't try to cache the response headers. */
      if ( strncmp( payload, "HTTP/", 5 ) != 0 )
        return IMP1_ENCODING_HASH;
    }
  } else if ( record_type == SSL3_RT_HANDSHAKE ) {
    /* The only usefully cacheable handshake type is Certificate.
       This is because other handshake types are either
         (1) dynamically generated, or
         (2) very short already.
       So we check whether the handshake begins with the Certificate code.
       Note that multiple handshakes can be packed into a single
       record, so theoretically this could cause a record with dynamic
       content to be cached.  However, in practice, I don't believe
       OpenSSL does this, and moreover, even if it did, it would not
       cause incorrectness, merely cache inefficiency. */
    if ( payload[0] == SSL3_MT_CERTIFICATE && payload_len > 20 )
      return IMP1_ENCODING_HASH;
  }
  return default_encoding; /* typically this should be
                              IMP1_ENCODING_NULL */
}


int
imp1_publish(int encoding,
             unsigned char *id,      int id_len,
             unsigned char *payload, int payload_len)
{
  char filename[255];
  char *fn = filename;
  FILE *f;

  fn += sprintf( filename, "%s/%i.", shared_data_directory, encoding );
  while (--id_len >= 0) { fn += sprintf( fn, "%02x", (unsigned int)(*id++) ); }

  if ( access( filename, R_OK ) == 0 ) return 1;

  f = fopen( filename, "wb" );
  if (f == NULL) { perror("imp1_publish: fopen"); return 0; }
  fwrite( payload, payload_len, 1, f );
  fclose( f );
  return 1;
}


int
imp1_encode_payload(int *encoding,
                    unsigned char *out, int *out_len,
                    unsigned char *in,  int  in_len,
                    int record_type,
                    int ssl_version)
{
  *encoding = imp1_choose_encoding( in, in_len, record_type, ssl_version );

  if (*encoding == IMP1_ENCODING_NULL) {

    memcpy(out, in, in_len);
    *out_len = in_len;

  } else if (*encoding == IMP1_ENCODING_SEQ) {

    static unsigned int data_identifier = 1;

    out[0] = (data_identifier >> 24) & 0xFF;
    out[1] = (data_identifier >> 16) & 0xFF;
    out[2] = (data_identifier >>  8) & 0xFF;
    out[3] = (data_identifier      ) & 0xFF;
    *out_len = 4;
    data_identifier++;

    imp1_publish( *encoding, out, *out_len, in, in_len );

  } else if (*encoding == IMP1_ENCODING_HASH) {

    static const EVP_MD *hash = NULL;
    EVP_MD_CTX md_ctx;

    if (hash == NULL) hash = EVP_get_digestbyname( "SHA1" );

    EVP_DigestInit(   &md_ctx, hash );
    EVP_DigestUpdate( &md_ctx,  in,  in_len );
    EVP_DigestFinal(  &md_ctx, out, out_len );

    imp1_publish( *encoding, out, *out_len, in, in_len );

  }
  return 1;
}


int
imp1_encode_record(unsigned char *out, int *out_len,
                   unsigned char *in,  int  in_len,
                   unsigned char *mac, int  mac_len,
                   int record_type,
                   int ssl_version)
{
  int encoding;
  int encoded_payload_len;

  if (!params_inited) {
    imp1_init_params();
    params_inited = 1;
  }

  imp1_encode_payload( &encoding, out+4, &encoded_payload_len, in, in_len,
                       record_type, ssl_version );
  *out++ = (encoding            >> 8) & 0xFF;
  *out++ = (encoding                ) & 0xFF;
  *out++ = (encoded_payload_len >> 8) & 0xFF;
  *out++ = (encoded_payload_len     ) & 0xFF;
  out += encoded_payload_len;

  *out++ = (mac_len >> 8) & 0xFF;
  *out++ = (mac_len     ) & 0xFF;

  memcpy(out, mac, mac_len);
  *out_len = 6 + encoded_payload_len + mac_len;

  return 1;
}
