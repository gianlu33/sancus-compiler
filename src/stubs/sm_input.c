#include "reactive_stubs_support.h"

#include <alloca.h>

void SM_ENTRY(SM_NAME) __sm_handle_input(conn_index conn_id,
                                         const void* payload, size_t len)
{
    // search for the connection.
    // Unfortunately, this operation is O(n) with n = number of connections
    int i;
    Connection *conn = NULL;
    for (i=0; i<__sm_num_connections; i++) {
      conn = &__sm_io_connections[i];

      if(conn->conn_id == conn_id)
        break;
    }

    if (i == __sm_num_connections)
      return; // connection not found

    if (conn->io_id >= SM_NUM_INPUTS)
        return;

    const size_t data_len = len - SANCUS_TAG_SIZE;
    const uint8_t* cipher = payload;
    const uint8_t* tag = cipher + data_len;

    // TODO check for stack overflow!
    uint8_t* input_buffer = alloca(data_len);

    if (sancus_unwrap_with_key(conn->key, &conn->nonce, sizeof(conn->nonce),
                               cipher, data_len, tag, input_buffer))
    {
        conn->nonce++;
        __sm_input_callbacks[conn->io_id](input_buffer, data_len);
    }
}
