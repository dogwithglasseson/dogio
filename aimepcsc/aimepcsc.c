#include "aimepcsc.h"
#include <stdio.h>

static const uint8_t atr_iso14443_common[] = {0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06};
static const uint8_t cardtype_m1k[] = {0x03, 0x00, 0x01};
static const uint8_t cardtype_felica[] = {0x11, 0x00, 0x3B};
static const uint8_t cardtype_ntag216[] = {0x03, 0x00, 0x03};
static const uint8_t cardtype_ultralight[] = {0x0C, 0x00, 0x3D};

static const uint8_t felica_cmd_readidm[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
static const uint8_t ntag216_cmd_get_uid[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
static const uint8_t ultralight_cmd_get_uid[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};

static const uint8_t m1k_cmd_get_uid[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
static const uint8_t m1k_cmd_loadkey[] = {0xFF, 0x82, 0x00, 0x00, 0x06, 0x57, 0x43, 0x43, 0x46, 0x76, 0x32};
static const uint8_t m1k_cmd_auth_block2[] = {0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x02, 0x61, 0x00};
static const uint8_t m1k_cmd_read_block2[] = {0xFF, 0xB0, 0x00, 0x02, 0x10};

struct aimepcsc_context {
    SCARDCONTEXT hContext;
    LPSTR mszReaders;
    DWORD pcchReaders;

    CHAR last_error[256];
};


static int apdu_send(struct aimepcsc_context *ctx, LPSCARDHANDLE card, const uint8_t *cmd, size_t cmd_len, uint8_t *buf, DWORD expected_res_len) {
    DWORD len = 32;
    LONG ret = SCardTransmit(*card, SCARD_PCI_T1, cmd, cmd_len, NULL, buf, &len);
    if (ret != SCARD_S_SUCCESS) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "SCardTransmit failed during %s: %08lX", cmd, (ULONG) ret);
        return -1;
    }
    if (len != expected_res_len || buf[expected_res_len - 2] != 0x90 || buf[expected_res_len - 1] != 0x00) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "%s failed; res_len=%lu, res_code=%02x%02x", cmd, len, buf[expected_res_len - 2], buf[expected_res_len - 1]);
        return 1;
    }
    return 0;
}

uint64_t hex_to_decimal(uint8_t *hex, size_t hex_len) {
    uint64_t decimal_value = 0;
    for (size_t i = 0; i < hex_len; ++i) {
        decimal_value = (decimal_value << 8) | hex[i];
    }
    return decimal_value;
}

void decimal_to_digit_array(uint64_t decimal, uint8_t *array, size_t array_len) {
    memset(array, 0, array_len);
    char decimal_str[21];
    snprintf(decimal_str, sizeof(decimal_str), "%llu", decimal);
    size_t decimal_len = strlen(decimal_str);
    for (size_t i = 0, j = 0; i < decimal_len && j < array_len; i += 2, ++j) {
        char temp[3] = {0};
        temp[0] = decimal_str[i];
        if (i + 1 < decimal_len) {
            temp[1] = decimal_str[i + 1];
        }
        array[j] = (uint8_t)strtol(temp, NULL, 16);
    }
    if ((array[0] & 0xF0) == 0x30) {
        array[0] = (array[0] & 0x0F) | 0x90;
    }
}

static int read_felica(struct aimepcsc_context *ctx, LPSCARDHANDLE card, struct aime_data *data) {
    uint8_t buf[32];
    LONG ret = apdu_send(ctx, card, felica_cmd_readidm, sizeof(felica_cmd_readidm), buf, 10);
    if (ret != 0) {
        return ret;
    }

    memcpy(data->card_id, buf, 8);
    data->card_id_len = 8;

    return 0;
}

static int read_m1k(struct aimepcsc_context *ctx, LPSCARDHANDLE card, struct aime_data *data) {
    uint8_t buf[32];
    LONG ret = apdu_send(ctx, card, m1k_cmd_get_uid, sizeof(m1k_cmd_get_uid), buf, 6);
    if (ret != 0) {
        return ret;
    }

    uint8_t card_uid[10];
    card_uid[0] = 0x00;
    card_uid[1] = 0x00;
    card_uid[2] = 0xF0;
    card_uid[3] = 0x01;
    card_uid[4] = 0x00;
    card_uid[5] = 0x00;
    memcpy(card_uid + 6, buf, 4);

    uint64_t decimal_value = hex_to_decimal(card_uid, 10);
    decimal_to_digit_array(decimal_value, data->card_id, 10);
    data->card_id_len = 10;

    return 0;
}

static int read_ntag216(struct aimepcsc_context *ctx, LPSCARDHANDLE card, struct aime_data *data) {
    uint8_t buf[32];
    LONG ret = apdu_send(ctx, card, ntag216_cmd_get_uid, sizeof(ntag216_cmd_get_uid), buf, 9);
    if (ret != 0) {
        return ret;
    }

    uint8_t card_uid[10];
    card_uid[0] = 0x00;
    card_uid[1] = 0x00;
    card_uid[2] = 0xF0;
    memcpy(card_uid + 3, buf, 7);

    uint64_t decimal_value = hex_to_decimal(card_uid, 10);
    decimal_to_digit_array(decimal_value, data->card_id, 10);
    data->card_id_len = 10;

    return 0;
}

static int read_ultralight(struct aimepcsc_context *ctx, LPSCARDHANDLE card, struct aime_data *data) {
    uint8_t buf[32];
    LONG ret = apdu_send(ctx, card, ultralight_cmd_get_uid, sizeof(ultralight_cmd_get_uid), buf, 10);
    if (ret != 0) {
        return ret;
    }

    uint8_t card_uid[10];
    card_uid[0] = 0x00;
    card_uid[1] = 0x00;
    memcpy(card_uid + 2, buf, 8);

    uint64_t decimal_value = hex_to_decimal(card_uid, 10);
    decimal_to_digit_array(decimal_value, data->card_id, 10);
    data->card_id_len = 10;

    return 0;
}

struct aimepcsc_context* aimepcsc_create(void) {
    struct aimepcsc_context* ctx;

    ctx = (struct aimepcsc_context*) malloc(sizeof(struct aimepcsc_context));
    if (!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(struct aimepcsc_context));
    return ctx;
}

void aimepcsc_destroy(struct aimepcsc_context *ctx) {
    free(ctx);
}

int aimepcsc_init(struct aimepcsc_context *ctx) {
    LONG ret;

    ret = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &ctx->hContext);

    if (ret != SCARD_S_SUCCESS) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "SCardEstablishContext failed: %08lX", (ULONG) ret);
        return -1;
    }

    ctx->pcchReaders = SCARD_AUTOALLOCATE;

    ret = SCardListReaders(ctx->hContext, NULL, (LPSTR) &ctx->mszReaders, &ctx->pcchReaders);

    if (ret != SCARD_S_SUCCESS) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "SCardListReaders failed: %08lX", (ULONG) ret);
        goto errout;
    }

    return 0;

errout:
    SCardReleaseContext(ctx->hContext);
    return -1;
}

void aimepcsc_shutdown(struct aimepcsc_context *ctx) {
    if (ctx->mszReaders != NULL) {
        SCardFreeMemory(ctx->hContext, ctx->mszReaders);
    }

    SCardReleaseContext(ctx->hContext);
}

int aimepcsc_poll(struct aimepcsc_context *ctx, struct aime_data *data) {
    SCARDHANDLE hCard;
    SCARD_READERSTATE rs;
    LONG ret;
    LPBYTE pbAttr = NULL;
    DWORD cByte = SCARD_AUTOALLOCATE;
    int retval;

    retval = 1;

    memset(&rs, 0, sizeof(SCARD_READERSTATE));

    rs.szReader = ctx->mszReaders;
    rs.dwCurrentState = SCARD_STATE_UNAWARE;

    /* check if a card is present */
    ret = SCardGetStatusChange(ctx->hContext, 0, &rs, 1);

    if (ret == SCARD_E_TIMEOUT) {
        return 1;
    }

    if (ret != SCARD_S_SUCCESS) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "SCardGetStatusChange failed: %08lX", (ULONG) ret);
        return -1;
    }

    if (rs.dwEventState & SCARD_STATE_EMPTY) {
        return 1;
    }

    if (!(rs.dwEventState & SCARD_STATE_PRESENT)) {
        sprintf(ctx->last_error, "unknown dwCurrentState: %08lX", rs.dwCurrentState);
        return -1;
    }

    /* connect to card */
    ret = SCardConnect(ctx->hContext, rs.szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, NULL);

    if (ret != SCARD_S_SUCCESS) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "SCardConnect failed: %08lX", (ULONG) ret);
        return -1;
    }

    /* get ATR string */
    ret = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, (LPBYTE) &pbAttr, &cByte);

    if (ret != SCARD_S_SUCCESS) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "SCardGetAttrib failed: %08lX", (ULONG) ret);
        return -1;
    }

    if (cByte != 20) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "invalid ATR length: %lu", cByte);
        goto out;
    }

    /* check ATR */
    if (memcmp(pbAttr, atr_iso14443_common, sizeof(atr_iso14443_common)) != 0) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "invalid card type.");
        goto out;
    }

    /* check card type */
    if (memcmp(pbAttr + sizeof(atr_iso14443_common), cardtype_m1k, sizeof(cardtype_m1k)) == 0) {
        data->card_type = Mifare;
        ret = read_m1k(ctx, &hCard, data);
        if (ret < 0) {
            retval = -1;
            goto out;
        } else if (ret > 0) {
            goto out;
        }
    } else if (memcmp(pbAttr + sizeof(atr_iso14443_common), cardtype_felica, sizeof(cardtype_felica)) == 0) {
        data->card_type = FeliCa;
        ret = read_felica(ctx, &hCard, data);
        if (ret < 0) {
            retval = -1;
            goto out;
        } else if (ret > 0) {
            goto out;
        }
    } else if (memcmp(pbAttr + sizeof(atr_iso14443_common), cardtype_ntag216, sizeof(cardtype_ntag216)) == 0) {
        data->card_type = Mifare;
        ret = read_ntag216(ctx, &hCard, data);
        if (ret < 0) {
            retval = -1;
            goto out;
        } else if (ret > 0) {
            goto out;
        }
    } else if (memcmp(pbAttr + sizeof(atr_iso14443_common), cardtype_ultralight, sizeof(cardtype_ultralight)) == 0) {
        data->card_type = Mifare;
        ret = read_ultralight(ctx, &hCard, data);
        if (ret < 0) {
            retval = -1;
            goto out;
        } else if (ret > 0) {
            goto out;
        }
    } else {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "invalid card type.");
        goto out;
    }

    retval = 0;

out:
    SCardFreeMemory(ctx->hContext, pbAttr);
    SCardDisconnect(hCard, SCARD_LEAVE_CARD);

    return retval;
}

const char* aimepcsc_error(struct aimepcsc_context *ctx) {
    return ctx->last_error;
}

const char* aimepcsc_reader_name(struct aimepcsc_context *ctx) {
    return ctx->mszReaders;
}