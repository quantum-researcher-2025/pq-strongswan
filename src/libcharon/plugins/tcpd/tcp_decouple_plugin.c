//
// Created by RIT WISP on 3/8/24.
//

#include "tcp_decouple_plugin.h"
#include "tcp_decouple_socket.h"
#include <daemon.h>

typedef struct private_tcp_decouple_plugin_t private_tcp_decouple_plugin_t;

struct private_tcp_decouple_plugin_t {
    tcp_decouple_plugin_t public;
};

METHOD(plugin_t, get_features, int, private_tcp_decouple_plugin_t *this, plugin_feature_t *features[]) {
    static plugin_feature_t f[] = {
        PLUGIN_CALLBACK(socket_register, tcp_decouple_socket_create),
        PLUGIN_PROVIDE(CUSTOM, "socket-tcp"),
        PLUGIN_SDEPEND(CUSTOM, "kernel-ipsec"),
    };
    *features = f;
    return countof(f);
}

METHOD(plugin_t, get_name, char*, private_tcp_decouple_plugin_t *this) {
    return "tcp_decouple";
}

METHOD(plugin_t, destroy, void, private_tcp_decouple_plugin_t *this) {
    free(this);
}

/*
 * see header file
 */
plugin_t *tcp_decouple_plugin_create() {
    private_tcp_decouple_plugin_t *this;
    INIT(this,
        .public = {
            .plugin = {
                .get_name = _get_name,
                .get_features = _get_features,
                .destroy = _destroy,
            },
        },
    );
    return &this->public.plugin;
}