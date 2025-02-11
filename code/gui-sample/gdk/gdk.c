#include <gdk/gdk.h>

int main(int argc, char *argv[]) {
    // Initialize GDK
    // GDK has to work across all platforms so two-phase initialization is needed
    // Note that in GDK 4 (this is GDK 3), gdk_init was removed as part of a restructuring
    // GTK still has gtk_init but it now takes no arguments
    gdk_init(&argc, &argv);

    // Create a new window using GdkWindowAttr
    GdkWindowAttr attributes;
    attributes.window_type = GDK_WINDOW_TOPLEVEL; // Create a top-level window
    attributes.width = 400;                       // Set the window width
    attributes.height = 300;                      // Set the window height
    attributes.wclass = GDK_INPUT_OUTPUT;         // Input-output window
    attributes.event_mask = GDK_EXPOSURE_MASK;    // Event mask for window exposure

    // Create the window
    GdkWindow *window = gdk_window_new(NULL, &attributes, GDK_WA_X | GDK_WA_Y);

    // Set window title
    gdk_window_set_title(window, "Simple GDK Window");

    // Show the window (make it visible)
    gdk_window_show(window);

    // Create a GdkEvent loop
    GdkEvent *event;
    gboolean running = TRUE;

    while (running) {
        // Wait for an event
        event = gdk_event_get();

        if (event != NULL) {
            // Handle events (e.g., closing the window)
            if (event->type == GDK_DELETE) {
                running = FALSE;
            }

            // Free the event structure after handling it
            gdk_event_free(event);
        }
    }

    // Destroy the window when done
    gdk_window_destroy(window);

    return 0;
}
