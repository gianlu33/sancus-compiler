#include "reactive_stubs_support.h"

void SM_ENTRY(SM_NAME) __sm_set_key(const uint8_t* ad, const uint8_t* cipher,
                                    const uint8_t* tag, uint8_t* result)
{
    conn_index conn_id = (ad[0] << 8) | ad[1];
    io_index io_id = (ad[2] << 8) | ad[3];
    ResultCode code = Ok;

    //TODO check nonce!! replay attacks

    // here i use a "fake" while loop to break the control flow if something
    // wrong happens
    while(1) {
      if (__sm_num_connections == SM_MAX_CONNECTIONS) {
        code = InternalError;
        break;
      }

      Connection *conn = &__sm_io_connections[__sm_num_connections];

      if (!sancus_unwrap(ad, 6, cipher, SANCUS_KEY_SIZE, tag, conn->key)) {
          code = MalformedPayload;
          break;
      }

      __sm_num_connections++;
      conn->io_id = io_id;
      conn->conn_id = conn_id;
      conn->nonce = 0;
      break;
    }

    result[0] = 0;
    result[1] = code;
    uint8_t result_ad[] = {ad[4], ad[5], result[0], result[1]};
    sancus_tag(result_ad, sizeof(result_ad), result + 2);
}
