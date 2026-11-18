/**
 * @file PROTOCOL_handshake.c
 * @brief Hybrid quantum-classical session authentication handshake implementation.
 */

#include "PROTOCOL_handshake.h"
#include <string.h>

static const uint8_t HKDF_INFO[] = "QSAC hybrid session key v1";
static const uint8_t TRANSCRIPT_PREFIX[] = "QSAC-TRANSCRIPT-v1:";

/* ----------------------------------------------
 * Static Transcript Buffer to eliminate stack load
 * ---------------------------------------------- */
typedef struct {
    uint8_t buffer[sizeof(TRANSCRIPT_PREFIX) + 2 * QSAC_NONCE_SIZE + 2 * QSAC_ECC_PUBKEY_SIZE + QSAC_MLKEM_PUBKEY_SIZE + QSAC_MLKEM_CIPHERTEXT_SIZE];
    uint8_t ecdh_shared[QSAC_ECC_SHARED_SECRET_SIZE];
    uint8_t mlkem_shared[QSAC_MLKEM_SHARED_SECRET_SIZE];
    uint8_t temp_pub[QSAC_ECC_PUBKEY_SIZE];
    uint8_t decrypted[QSAC_HANDSHAKE_CONFIRMATION_SIZE];
} handshake_workspace_t;

static handshake_workspace_t hs_ws;

static qsac_status_t compute_transcript_hash(
    const uint8_t *client_nonce,
    const uint8_t *server_nonce,
    const uint8_t *client_ecdh_pub,
    const uint8_t *server_ecdh_pub,
    const uint8_t *client_mlkem_pub,
    const uint8_t *server_mlkem_ct,
    uint8_t *out_hash)
{
    size_t offset = 0;

    memcpy(hs_ws.buffer + offset, TRANSCRIPT_PREFIX, sizeof(TRANSCRIPT_PREFIX) - 1);
    offset += sizeof(TRANSCRIPT_PREFIX) - 1;

    memcpy(hs_ws.buffer + offset, client_nonce, QSAC_NONCE_SIZE);
    offset += QSAC_NONCE_SIZE;

    memcpy(hs_ws.buffer + offset, server_nonce, QSAC_NONCE_SIZE);
    offset += QSAC_NONCE_SIZE;

    memcpy(hs_ws.buffer + offset, client_ecdh_pub, QSAC_ECC_PUBKEY_SIZE);
    offset += QSAC_ECC_PUBKEY_SIZE;

    memcpy(hs_ws.buffer + offset, server_ecdh_pub, QSAC_ECC_PUBKEY_SIZE);
    offset += QSAC_ECC_PUBKEY_SIZE;

    memcpy(hs_ws.buffer + offset, client_mlkem_pub, QSAC_MLKEM_PUBKEY_SIZE);
    offset += QSAC_MLKEM_PUBKEY_SIZE;

    memcpy(hs_ws.buffer + offset, server_mlkem_ct, QSAC_MLKEM_CIPHERTEXT_SIZE);
    offset += QSAC_MLKEM_CIPHERTEXT_SIZE;

    return qsac_sha256(hs_ws.buffer, offset, out_hash);
}

qsac_status_t qsac_handshake_client_init(qsac_handshake_client_ctx_t *ctx, uint32_t ecdh_slot)
{
    if (!ctx) {
        return QSAC_ERR_INVALID_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->ecdh_key_slot = ecdh_slot;
    ctx->state = QSAC_HS_STATE_INIT;
    return QSAC_OK;
}

qsac_status_t qsac_handshake_client_create_hello(qsac_handshake_client_ctx_t *ctx,
                                                 qsac_client_hello_t *hello)
{
    qsac_status_t status;

    if (!ctx || !hello || ctx->state != QSAC_HS_STATE_INIT) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* Generate Client Nonce */
    status = qsac_random_bytes(ctx->client_nonce, QSAC_NONCE_SIZE);
    if (status != QSAC_OK) {
        ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }
    memcpy(hello->client_nonce, ctx->client_nonce, QSAC_NONCE_SIZE);

    /* Generate Ephemeral ECDH P-256 Keypair */
    status = qsac_ecc_keygen(ctx->ecdh_key_slot, hello->ecdh_pubkey);
    if (status != QSAC_OK) {
        ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Generate Ephemeral ML-KEM-512 Keypair */
    status = qsac_mlkem_keygen(hello->mlkem_pubkey, ctx->mlkem_privkey);
    if (status != QSAC_OK) {
        ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Save Client Public Keys for Transcript Hashing */
    memcpy(ctx->ecdh_pubkey, hello->ecdh_pubkey, QSAC_ECC_PUBKEY_SIZE);
    memcpy(ctx->mlkem_pubkey, hello->mlkem_pubkey, QSAC_MLKEM_PUBKEY_SIZE);

    ctx->state = QSAC_HS_STATE_HELLO_SENT;
    return QSAC_OK;
}

qsac_status_t qsac_handshake_server_process_hello_and_respond(
    qsac_handshake_server_ctx_t *server_ctx,
    uint32_t server_ecdh_slot,
    const uint8_t *server_mldsa_privkey,
    const qsac_client_hello_t *client_hello,
    qsac_server_hello_t *server_hello)
{
    qsac_status_t status;

    if (!server_ctx || !server_mldsa_privkey || !client_hello || !server_hello) {
        return QSAC_ERR_INVALID_PARAM;
    }

    memset(server_ctx, 0, sizeof(*server_ctx));
    server_ctx->ecdh_key_slot = server_ecdh_slot;
    memcpy(server_ctx->client_nonce, client_hello->client_nonce, QSAC_NONCE_SIZE);

    /* Generate Server Nonce */
    status = qsac_random_bytes(server_ctx->server_nonce, QSAC_NONCE_SIZE);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }
    memcpy(server_hello->server_nonce, server_ctx->server_nonce, QSAC_NONCE_SIZE);

    /* Generate Server Ephemeral ECDH Keypair */
    status = qsac_ecc_keygen(server_ctx->ecdh_key_slot, server_hello->ecdh_pubkey);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Compute ECDH Shared Secret */
    status = qsac_ecdh(server_ctx->ecdh_key_slot, client_hello->ecdh_pubkey, hs_ws.ecdh_shared);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Encapsulate ML-KEM-512 Key */
    status = qsac_mlkem_encaps(client_hello->mlkem_pubkey,
                               server_hello->mlkem_ciphertext,
                               hs_ws.mlkem_shared);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Combine via HKDF-SHA-256 */
    status = qsac_hkdf_combine(hs_ws.ecdh_shared,
                               hs_ws.mlkem_shared,
                               HKDF_INFO,
                               sizeof(HKDF_INFO) - 1,
                               server_ctx->session_key);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Compute Transcript Hash */
    status = compute_transcript_hash(
        client_hello->client_nonce,
        server_hello->server_nonce,
        client_hello->ecdh_pubkey,
        server_hello->ecdh_pubkey,
        client_hello->mlkem_pubkey,
        server_hello->mlkem_ciphertext,
        server_ctx->transcript_hash);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Sign Transcript Hash with Server ML-DSA-44 Key */
    status = qsac_mldsa_sign(server_mldsa_privkey,
                             server_ctx->transcript_hash,
                             sizeof(server_ctx->transcript_hash),
                             server_hello->mldsa_signature);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Zeroize ephemeral secrets */
    memset(hs_ws.ecdh_shared, 0, sizeof(hs_ws.ecdh_shared));
    memset(hs_ws.mlkem_shared, 0, sizeof(hs_ws.mlkem_shared));

    server_ctx->state = QSAC_HS_STATE_SERVER_RESPONDED;
    return QSAC_OK;
}

qsac_status_t qsac_handshake_client_process_server_hello(
    qsac_handshake_client_ctx_t *client_ctx,
    const uint8_t *server_mldsa_pubkey,
    const qsac_server_hello_t *server_hello,
    qsac_client_finished_t *client_finished)
{
    qsac_status_t status;

    if (!client_ctx || !server_mldsa_pubkey || !server_hello || !client_finished ||
        client_ctx->state != QSAC_HS_STATE_HELLO_SENT) {
        return QSAC_ERR_INVALID_PARAM;
    }

    memcpy(client_ctx->server_nonce, server_hello->server_nonce, QSAC_NONCE_SIZE);

    /* Compute transcript hash using client's saved public keys and server's response */
    status = compute_transcript_hash(
        client_ctx->client_nonce,
        server_hello->server_nonce,
        client_ctx->ecdh_pubkey,
        server_hello->ecdh_pubkey,
        client_ctx->mlkem_pubkey,
        server_hello->mlkem_ciphertext,
        client_ctx->transcript_hash);
    if (status != QSAC_OK) {
        client_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Verify Server's ML-DSA-44 Signature over Transcript */
    status = qsac_mldsa_verify(server_mldsa_pubkey,
                               client_ctx->transcript_hash,
                               sizeof(client_ctx->transcript_hash),
                               server_hello->mldsa_signature);
    if (status != QSAC_OK) {
        client_ctx->state = QSAC_HS_STATE_FAILED;
        return QSAC_ERR_VERIFY_FAIL;
    }

    /* Compute Client ECDH Shared Secret */
    status = qsac_ecdh(client_ctx->ecdh_key_slot, server_hello->ecdh_pubkey, hs_ws.ecdh_shared);
    if (status != QSAC_OK) {
        client_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Decapsulate ML-KEM Shared Secret */
    status = qsac_mlkem_decaps(client_ctx->mlkem_privkey,
                               server_hello->mlkem_ciphertext,
                               hs_ws.mlkem_shared);
    if (status != QSAC_OK) {
        client_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Derive Matching Hybrid Session Key */
    status = qsac_hkdf_combine(hs_ws.ecdh_shared,
                               hs_ws.mlkem_shared,
                               HKDF_INFO,
                               sizeof(HKDF_INFO) - 1,
                               client_ctx->session_key);
    if (status != QSAC_OK) {
        client_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    /* Zeroize ephemeral secrets */
    memset(hs_ws.ecdh_shared, 0, sizeof(hs_ws.ecdh_shared));
    memset(hs_ws.mlkem_shared, 0, sizeof(hs_ws.mlkem_shared));
    memset(client_ctx->mlkem_privkey, 0, sizeof(client_ctx->mlkem_privkey));

    /* Prepare ClientFinished message encrypted with AES-256-GCM */
    status = qsac_random_bytes(client_finished->iv, QSAC_AES_IV_SIZE);
    if (status != QSAC_OK) {
        client_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    status = qsac_aes_gcm_encrypt(client_ctx->session_key,
                                  client_finished->iv,
                                  NULL, 0,
                                  client_ctx->transcript_hash,
                                  sizeof(client_ctx->transcript_hash),
                                  client_finished->encrypted_confirmation,
                                  client_finished->tag);
    if (status != QSAC_OK) {
        client_ctx->state = QSAC_HS_STATE_FAILED;
        return status;
    }

    client_ctx->state = QSAC_HS_STATE_ESTABLISHED;
    return QSAC_OK;
}

qsac_status_t qsac_handshake_server_process_finished(
    qsac_handshake_server_ctx_t *server_ctx,
    const qsac_client_finished_t *client_finished)
{
    qsac_status_t status;

    if (!server_ctx || !client_finished || server_ctx->state != QSAC_HS_STATE_SERVER_RESPONDED) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* Decrypt and authenticate ClientFinished message */
    status = qsac_aes_gcm_decrypt(server_ctx->session_key,
                                  client_finished->iv,
                                  NULL, 0,
                                  client_finished->encrypted_confirmation,
                                  sizeof(client_finished->encrypted_confirmation),
                                  client_finished->tag,
                                  hs_ws.decrypted);
    if (status != QSAC_OK) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return QSAC_ERR_VERIFY_FAIL;
    }

    /* Verify confirmation payload matches expected transcript hash */
    if (memcmp(hs_ws.decrypted, server_ctx->transcript_hash, sizeof(server_ctx->transcript_hash)) != 0) {
        server_ctx->state = QSAC_HS_STATE_FAILED;
        return QSAC_ERR_VERIFY_FAIL;
    }

    server_ctx->state = QSAC_HS_STATE_ESTABLISHED;
    return QSAC_OK;
}
