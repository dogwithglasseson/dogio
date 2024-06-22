#include <signal.h>

#include "aimepcsc.h"
#include <stdio.h>

struct aimepcsc_context* ctx;

void cleanup_and_exit(int signal) {
    fprintf(stderr, "Received signal %d, shutting down...\n", signal);
    if (ctx) {
        aimepcsc_shutdown(ctx);
        aimepcsc_destroy(ctx);
    }
    exit(0);
}

int main(int argc, char** argv) {

    int ret;

    ctx = aimepcsc_create();
    if (!ctx) {
        return -1;
    }

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    ret = aimepcsc_init(ctx);
    if (ret != 0) {
        fprintf(stderr, "aimepcsc_init failed: %s\n", aimepcsc_error(ctx));
        return -1;
    }

    fprintf(stderr, "connected to reader: %s; waiting for cards...\n", aimepcsc_reader_name(ctx));

    while (1) {
        struct aime_data data;

        ret = aimepcsc_poll(ctx, &data);
        if (ret == 0) {
            printf("card detected: ");
            printf("type=%s, id=", data.card_type == Mifare ? "Mifare (old Aime)" : "FeliCa (AIC-Aime)");
            for (int i = 0; i < data.card_id_len; i++) {
                printf("%02X", data.card_id[i]);
            }
            printf("\n");
        } else if (ret == -1) {
            fprintf(stderr, "aimepcsc_poll failed: %s\n", aimepcsc_error(ctx));
            //break;
        }

        Sleep(500);
    }

    // this never gets reached idk
    aimepcsc_shutdown(ctx);
    aimepcsc_destroy(ctx);
    return 0;
}