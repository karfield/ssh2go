#ifndef __CALLBACKS_H__
#define __CALLBACKS_H__

struct ssh_bind_callbacks_struct_wrapper {
    struct ssh_bind_callbacks_struct callbacks;
    void *userdata;
};

typedef struct ssh_bind_callbacks_struct_wrapper *ssh_bind_callbacks_wrapper;

ssh_bind_callbacks_wrapper new_bind_callbacks();
void install_bind_incoming_connection_callback(ssh_bind_callbacks cbs);
void set_bind_callbacks(ssh_bind sshbind, ssh_bind_callbacks_wrapper callbacks);

#endif
