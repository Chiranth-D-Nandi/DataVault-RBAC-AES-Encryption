#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include "enc.h"
#include "dec.h"

// Globals for staff/admin windows
GtkWidget *main_window, *status_label;
char current_user[100] = "";
char current_role[16] = "";

// ==== Utility for Logging ====
void log_encryption(const char *username, const char *file_encrypted) {
    FILE *fap = fopen("access_log.csv", "a");
    if (!fap) return;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(fap, "%s,%s,%02d-%02d-%04d %02d:%02d:%02d\n",
        username,
        file_encrypted,
        t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,
        t->tm_hour, t->tm_min, t->tm_sec
    );
    fclose(fap);
}

// ==== Login/Register Widgets ====
struct logindata {
    GtkWidget *user_entry;
    GtkWidget *pass_entry;
    GtkWidget *roles;
    GtkWidget *window;
};
GtkWidget *login_user_entry, *login_pass_entry;

// ==== Forward Declarations ====
void open_swin();
void open_awin();
void show_main_window();

// ==== Register Logic ====
void validate_register(GtkWidget *widget, gpointer data){
    struct logindata *rdata = (struct logindata *)data;
    const char *username = gtk_entry_get_text(GTK_ENTRY(rdata->user_entry));
    const char *password = gtk_entry_get_text(GTK_ENTRY(rdata->pass_entry));
    const char *role = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(rdata->roles));
    if (strlen(password) < 8){
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Password must be at least 8 characters long.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }
    int spl_char = 0;
    for (int i = 0; i < strlen(password); i++) {
        if (!isalnum(password[i])){
            spl_char = 1; break;
        }
    }
    if(spl_char == 0){
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Password must contain at least 1 special char!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }
    FILE *fp = fopen("userda.txt", "a");
    if (fp != NULL){
        fprintf(fp, "%s %s %s\n", username, password, role);
        fclose(fp);
    }
    GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "User registered successfully!!");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    gtk_widget_destroy(rdata->window);
}

// ==== Register Window ====
void show_register_fields(GtkWidget *widget, gpointer data){
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Register New User");
    gtk_window_set_default_size(GTK_WINDOW(window), 300, 200);
    GtkWidget *vbox2 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(window), vbox2);
    GtkWidget *user_label = gtk_label_new("Username: ");
    GtkWidget *user_entry = gtk_entry_new();
    GtkWidget *pass_label = gtk_label_new("Password: ");
    GtkWidget *pass_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(pass_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(pass_entry), '*');
    GtkWidget *sub = gtk_button_new_with_label("Submit");
    gtk_box_pack_start(GTK_BOX(vbox2), user_label, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox2), user_entry, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox2), pass_label, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox2), pass_entry, FALSE, FALSE, 5);
    GtkWidget *role_label = gtk_label_new("Role: ");
    GtkWidget *roles = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(roles), "staff");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(roles), "admin");
    gtk_combo_box_set_active(GTK_COMBO_BOX(roles), 0);
    gtk_box_pack_start(GTK_BOX(vbox2), role_label, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox2), roles, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox2), sub, FALSE, FALSE, 10);
    struct logindata *rdata = g_malloc(sizeof(struct logindata));
    rdata->user_entry = user_entry;
    rdata->pass_entry = pass_entry;
    rdata->roles = roles;
    rdata->window = window;
    g_signal_connect(sub, "clicked", G_CALLBACK(validate_register), rdata);
    gtk_widget_show_all(window);
}

// ==== Login Logic ====
void validate_login(GtkWidget *widget, gpointer data) {
    const char *username = gtk_entry_get_text(GTK_ENTRY(login_user_entry));
    const char *password = gtk_entry_get_text(GTK_ENTRY(login_pass_entry));
    if (strlen(username) == 0 || strlen(password) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Username or password cannot be empty!");
        return;
    }
    FILE *fp = fopen("userda.txt", "r");
    if (!fp) {
        gtk_label_set_text(GTK_LABEL(status_label), "No users registered yet.");
        return;
    }
    char file_user[100], file_pass[100], file_role[50];
    int found = 0;
    while (fscanf(fp, "%99s %99s %49s", file_user, file_pass, file_role) != EOF){
        if (strcmp(username, file_user)==0 && strcmp(password, file_pass)==0){
            found = 1;
            break;
        }
    }
    fclose(fp);
    if (found) {
        snprintf(current_user, sizeof(current_user), "%s", username);
        snprintf(current_role, sizeof(current_role), "%s", file_role);
        char msg[200];
        snprintf(msg, sizeof(msg), "Login Successful! Welcome %s (%s)", username, file_role);
        gtk_label_set_text(GTK_LABEL(status_label), msg);
        gtk_widget_hide(main_window);
        if (strcmp(file_role, "admin") == 0) open_awin();
        else open_swin();
    } else {
        gtk_label_set_text(GTK_LABEL(status_label), "Invalid username or password!");
    }
}

// ==== Main/Login Window ====
void show_main_window() {
    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "Data Vault: Encryption & RBAC");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 400, 370);
    g_signal_connect(main_window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(main_window), vbox);

    // Load and scale image
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file_at_scale("logo.png", 128, 128, TRUE, NULL);
    GtkWidget *imag = gtk_image_new_from_pixbuf(pixbuf);
    if (pixbuf) g_object_unref(pixbuf);
    gtk_box_pack_start(GTK_BOX(vbox), imag, FALSE, FALSE, 10);

    GtkWidget *user_label = gtk_label_new("Username: ");
    login_user_entry = gtk_entry_new();
    GtkWidget *pass_label = gtk_label_new("Password: ");
    login_pass_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(login_pass_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(login_pass_entry), '*');
    GtkWidget *login_btn = gtk_button_new_with_label("Sign In");
    GtkWidget *register_btn = gtk_button_new_with_label("Register New Staff/User");

    gtk_box_pack_start(GTK_BOX(vbox), user_label, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), login_user_entry, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), pass_label, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), login_pass_entry, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), login_btn, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), register_btn, FALSE, FALSE, 5);

    status_label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(vbox), status_label, FALSE, FALSE, 2);

    g_signal_connect(login_btn, "clicked", G_CALLBACK(validate_login), NULL);
    g_signal_connect(register_btn, "clicked", G_CALLBACK(show_register_fields), NULL);
    gtk_widget_show_all(main_window);
}

// ==== Staff Window ====
GtkWidget *swin, *choose, *selectf, *logout_btn, *status_label_staff;
gchar *selected_filepath = NULL;
void logout_to_login(GtkWidget *widget, gpointer user_data) {
    gtk_widget_destroy(swin);
    show_main_window();
}
void on_upload_clicked(GtkWidget *widget, gpointer user_data) {
    selected_filepath = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(choose));
    if (!selected_filepath) {
        gtk_label_set_text(GTK_LABEL(status_label_staff), "Please select a file first.");
        return;
    }
    gtk_label_set_text(GTK_LABEL(status_label_staff), "Encrypting...");
    int ret = final(selected_filepath);
    if (ret == 0) {
        gtk_label_set_text(GTK_LABEL(status_label_staff), "File encrypted successfully.");
        if (remove(selected_filepath) == 0) {
            gtk_label_set_text(GTK_LABEL(status_label_staff), "File encrypted and original deleted.");
        } else {
            gtk_label_set_text(GTK_LABEL(status_label_staff), "File encrypted, but deletion failed.");
        }
        const char *file_name = g_path_get_basename(selected_filepath);
        log_encryption(current_user, file_name);
    } else {
        gtk_label_set_text(GTK_LABEL(status_label_staff), "Encryption failed.");
    }
    g_free(selected_filepath);
    selected_filepath = NULL;
}
void open_swin() {
    swin = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(swin), "Staff Interface - Upload to Vault");
    gtk_window_set_default_size(GTK_WINDOW(swin), 400, 250);
    gtk_container_set_border_width(GTK_CONTAINER(swin), 10);
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(swin), vbox);

    GtkWidget *upload_label = gtk_label_new("Upload File to Vault:");
    gtk_box_pack_start(GTK_BOX(vbox), upload_label, FALSE, FALSE, 0);

    choose = gtk_file_chooser_button_new("Choose a file", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_box_pack_start(GTK_BOX(vbox), choose, FALSE, FALSE, 0);
    selectf = gtk_button_new_with_label("Upload to Vault");
    gtk_box_pack_start(GTK_BOX(vbox), selectf, FALSE, FALSE, 0);
    status_label_staff = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(vbox), status_label_staff, FALSE, FALSE, 0);
    logout_btn = gtk_button_new_with_label("Logout");
    gtk_box_pack_start(GTK_BOX(vbox), logout_btn, FALSE, FALSE, 0);
    g_signal_connect(selectf, "clicked", G_CALLBACK(on_upload_clicked), NULL);
    g_signal_connect(logout_btn, "clicked", G_CALLBACK(logout_to_login), NULL);
    gtk_widget_show_all(swin);
}

// ==== Admin Window ====
GtkWidget *awin, *choose_enc, *choose_key, *decrypt_btn, *logout_btn_admin, *status_label_admin;
gchar *selected_enc_file = NULL, *selected_key_file = NULL;
GtkWidget *logbtn, *log_text_view, *log_scroll_win;
void logout_admin(GtkWidget *widget, gpointer user_data) {
    gtk_widget_destroy(awin);
    show_main_window();
}
void on_decrypt_clicked(GtkWidget *widget, gpointer user_data) {
    selected_enc_file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(choose_enc));
    selected_key_file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(choose_key));
    if (!selected_enc_file || !selected_key_file) {
        gtk_label_set_text(GTK_LABEL(status_label_admin), "Select both encrypted file and key file.");
        if (selected_enc_file) g_free(selected_enc_file);
        if (selected_key_file) g_free(selected_key_file);
        return;
    }
    gtk_label_set_text(GTK_LABEL(status_label_admin), "Decrypting...");
    int result = decrypt(selected_enc_file, selected_key_file);
    if (result == 0)
        gtk_label_set_text(GTK_LABEL(status_label_admin), "Decryption successful.");
    else
        gtk_label_set_text(GTK_LABEL(status_label_admin), "Decryption failed.");
    g_free(selected_enc_file);
    g_free(selected_key_file);
    selected_enc_file = NULL;
    selected_key_file = NULL;
}
void on_view_log_clicked(GtkWidget *widget, gpointer user_data) {
    FILE *f = fopen("access_log.csv", "r");
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(log_text_view));
    if (!f) {
        gtk_text_buffer_set_text(buffer, "Failed to open access_log.csv", -1);
        return;
    }
    char line[1024];
    GString *content = g_string_new("");
    while (fgets(line, sizeof(line), f)) {
        g_string_append(content, line);
    }
    fclose(f);
    gtk_text_buffer_set_text(buffer, content->str, -1);
    g_string_free(content, TRUE);
}
void open_awin() {
    awin = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(awin), "Admin Interface - Decrypt Vault File");
    gtk_window_set_default_size(GTK_WINDOW(awin), 600, 400);
    gtk_container_set_border_width(GTK_CONTAINER(awin), 10);
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(awin), vbox);

    // Label and chooser for encrypted file
    GtkWidget *enc_label = gtk_label_new("Upload Encrypted File:");
    gtk_box_pack_start(GTK_BOX(vbox), enc_label, FALSE, FALSE, 0);
    choose_enc = gtk_file_chooser_button_new("Choose Encrypted File", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_box_pack_start(GTK_BOX(vbox), choose_enc, FALSE, FALSE, 0);

    // Label and chooser for key file
    GtkWidget *key_label = gtk_label_new("Upload Key File:");
    gtk_box_pack_start(GTK_BOX(vbox), key_label, FALSE, FALSE, 0);
    choose_key = gtk_file_chooser_button_new("Choose Key File", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_box_pack_start(GTK_BOX(vbox), choose_key, FALSE, FALSE, 0);

    decrypt_btn = gtk_button_new_with_label("Decrypt File");
    gtk_box_pack_start(GTK_BOX(vbox), decrypt_btn, FALSE, FALSE, 0);
    logbtn = gtk_button_new_with_label("View Access Logs");
    gtk_box_pack_start(GTK_BOX(vbox), logbtn, FALSE, FALSE, 0);

    log_scroll_win = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(log_scroll_win, TRUE);
    gtk_widget_set_hexpand(log_scroll_win, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), log_scroll_win, TRUE, TRUE, 0);
    log_text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(log_text_view), FALSE);
    gtk_container_add(GTK_CONTAINER(log_scroll_win), log_text_view);

    status_label_admin = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(vbox), status_label_admin, FALSE, FALSE, 0);
    logout_btn_admin = gtk_button_new_with_label("Logout");
    gtk_box_pack_start(GTK_BOX(vbox), logout_btn_admin, FALSE, FALSE, 0);

    g_signal_connect(decrypt_btn, "clicked", G_CALLBACK(on_decrypt_clicked), NULL);
    g_signal_connect(logbtn, "clicked", G_CALLBACK(on_view_log_clicked), NULL);
    g_signal_connect(logout_btn_admin, "clicked", G_CALLBACK(logout_admin), NULL);

    gtk_widget_show_all(awin);
}

// ==== Main Entrypoint ====
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    show_main_window();
    gtk_main();
    return 0;
}