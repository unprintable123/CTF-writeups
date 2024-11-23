#include <gio/gio.h>
#include <glib.h>

static gchar *flag1;
static gchar *flag2;
static gchar *flag3;

static void respond_success(GDBusMethodInvocation *invocation,
                            const gchar *msg) {
  g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", msg));
}

static void respond_error(GDBusMethodInvocation *invocation,
                          const GError *error) {
  g_dbus_method_invocation_return_error(invocation, error->domain, error->code,
                                        "%s", error->message);
}

static void respond_error_msg(GDBusMethodInvocation *invocation,
                              const gchar *msg) {
  GError *error = NULL;
  g_set_error(&error, G_IO_ERROR, G_IO_ERROR_UNKNOWN, "%s", msg);
  respond_error(invocation, error);
}

static void handle_method_call(GDBusConnection *connection, const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *method_name, GVariant *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer user_data) {
  if (g_strcmp0(method_name, "GetFlag1") == 0) {
    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(s)"))) {
      return respond_error_msg(invocation, "Give me a string, please.");
    }
    gchar *input;
    g_variant_get(parameters, "(&s)", &input);
    if (g_strcmp0(input, "Please give me flag1") != 0) {
      return respond_error_msg(
          invocation, "Use input 'Please give me flag1' to get flag1!");
    } else {
      return respond_success(invocation, flag1);
    }
  } else if (g_strcmp0(method_name, "GetFlag2") == 0) {
    if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(h)"))) {
      return respond_error_msg(invocation,
                               "Give me a file descriptor, please.");
    }
    gint fd_index;
    g_variant_get(parameters, "(h)", &fd_index);
    GUnixFDList *fd_list = g_dbus_message_get_unix_fd_list(
        g_dbus_method_invocation_get_message(invocation));
    if (!fd_list) {
      return respond_error_msg(
          invocation, "I want a GUnixFDList but you don't give that to me :(");
    }
    gint fd = g_unix_fd_list_get(fd_list, fd_index, NULL);

    // Validate the fd is NOT on filesystem
    gchar path[1024];
    g_snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    gchar *link = g_file_read_link(path, NULL);
    if (link != NULL) {
      if (g_strstr_len(link + 1, -1, "/") != 0) {
        return respond_error_msg(
            invocation, "Please don't give me a file on disk to trick me!");
      }
    } else {
      return respond_error_msg(invocation, "Readlink of given FD failed.");
    }

    char buffer[100];
    ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (len == -1) {
      return respond_error_msg(invocation,
                               "Cannot read from your file descriptor.");
    } else {
      buffer[len] = 0;
    }

    if (g_strcmp0(buffer, "Please give me flag2\n") != 0) {
      return respond_error_msg(
          invocation,
          "Please give me file descriptor with that message to get flag!");
    } else {
      return respond_success(invocation, flag2);
    }

    g_assert(0);
  } else if (g_strcmp0(method_name, "GetFlag3") == 0) {
    const gchar *caller_name = g_dbus_method_invocation_get_sender(invocation);
    GError *error = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixProcessID",
        g_variant_new("(s)", caller_name), G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
    if (result == NULL) {
      return respond_error(invocation, error);
    }
    guint32 pid;
    g_variant_get(result, "(u)", &pid);
    g_variant_unref(result);

    char path[1024];
    g_snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    gchar *comm;
    gsize len;
    if (g_file_get_contents(path, &comm, &len, &error)) {
      if (g_strcmp0(comm, "getflag3\n") != 0) {
        return respond_error_msg(invocation,
                                 "You shall use getflag3 to call me!");
      } else {
        return respond_success(invocation, flag3);
      }
    } else {
      return respond_error(invocation, error);
    }

    g_assert(0);
  }
}

static const GDBusInterfaceVTable interface_vtable = {
    handle_method_call,
    NULL,
    NULL,
};

static const gchar introspection_xml[] =
    "<?xml version='1.0' encoding='UTF-8'?>"
    "<node>"
    "  <interface name='cn.edu.ustc.lug.hack.FlagService'>"
    "    <method name='GetFlag1'>"
    "      <arg type='s' name='input' direction='in'/>"
    "      <arg type='s' name='response' direction='out'/>"
    "    </method>"
    "    <method name='GetFlag2'>"
    "      <arg type='h' name='fd' direction='in'/>"
    "      <arg type='s' name='response' direction='out'/>"
    "    </method>"
    "    <method name='GetFlag3'>"
    "      <arg type='s' name='response' direction='out'/>"
    "    </method>"
    "  </interface>"
    "</node>";

static int bus_acquired = 0;

static void on_bus_acquired(GDBusConnection *connection, const gchar *name,
                            gpointer user_data) {
  bus_acquired = 1;
  GError *error = NULL;

  GDBusNodeInfo *introspection_data =
      g_dbus_node_info_new_for_xml(introspection_xml, &error);
  if (error != NULL) {
    g_printerr("Failed to parse introspection XML: %s\n", error->message);
    g_clear_error(&error);
    return;
  }

  g_dbus_connection_register_object(connection,
                                    "/cn/edu/ustc/lug/hack/FlagService",
                                    introspection_data->interfaces[0],
                                    &interface_vtable, NULL, /* user_data */
                                    NULL, /* GDestroyNotify */
                                    &error);

  if (error != NULL) {
    g_printerr("Failed to register object: %s\n", error->message);
    g_clear_error(&error);
    return;
  }
}

static void on_name_acquired(GDBusConnection *connection, const gchar *name,
                             gpointer user_data) {
  g_print("Name acquired: %s\n", name);
}

static void on_name_lost(GDBusConnection *connection, const gchar *name,
                         gpointer user_data) {
  if (!connection) {
    g_printerr("connection to bus cannot be made\n");
  }
  if (!bus_acquired) {
    g_printerr("name cannot be obtained\n");
  }
  g_printerr("Name lost: %s\n", name);
}

static void read_flag(const char *filename, char **flag) {
  gsize len;
  GError *error = NULL;
  if (!g_file_get_contents(filename, flag, &len, &error)) {
    g_printerr("Error reading %s: %s\n", filename, error->message);
    g_error_free(error);
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  GMainLoop *loop;
  guint owner_id;

  // Read flags
  read_flag("/flag1", &flag1);
  read_flag("/flag2", &flag2);
  read_flag("/flag3", &flag3);

  owner_id =
      g_bus_own_name(G_BUS_TYPE_SYSTEM, "cn.edu.ustc.lug.hack.FlagService",
                     G_BUS_NAME_OWNER_FLAGS_NONE, on_bus_acquired,
                     on_name_acquired, on_name_lost, NULL, NULL);

  loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);

  g_bus_unown_name(owner_id);
  g_main_loop_unref(loop);

  return 0;
}
