/*
 * Automatic Attachment Encryption Plug-in for Sylpheed
 * Copyright (C) 2016 Sylpheed Development Team
 * Copyright (C) 2016-2017 Hiroyuki Yamamoto
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#ifdef G_OS_WIN32
#  include <windows.h>
#  include <winreg.h>
#  include <wchar.h>
#endif

#include "sylmain.h"
#include "prefs_common.h"
#include "plugin.h"
#include "prefs.h"
#include "autoenc.h"
#include "md5.h"
#include "base64.h"
#include "procmsg.h"
#include "procheader.h"

#include "send_enc.h"

static SylPluginInfo info = {
	"Automatic Attachment Encryption Plug-in",
	VERSION,
	"Hiroyuki Yamamoto",
	"Automatically encrypt attachments when sending mails"
};

static AppConfig config;

static PrefParam param[] = {
	{"enable_autoenc", "TRUE", &config.enable_autoenc, P_BOOL},
	{"autoenc_template_subject", NULL, &config.autoenc_template_subject, P_STRING},
	{"autoenc_template_body", NULL, &config.autoenc_template_body, P_STRING},
	{"force_encryption", "FALSE", &config.force_encryption, P_BOOL},
	{NULL, NULL, NULL, P_OTHER}
};

static void init_done_cb(GObject *obj, gpointer data);
static void app_exit_cb(GObject *obj, gpointer data);

static const gchar *get_autoenc_tmp_dir(void);
static void read_config(void);
static void write_config(void);
static void add_button(gpointer compose);
static gchar *generate_password(void);
static void send_with_encryption(gpointer compose);
static GtkWidget *autoenc_processing_dialog_create(void);
static void autoenc_settings_dialog(void);

static gchar *replace_template_string(const gchar *template,
				      const gchar *subject,
				      const gchar *date,
				      const gchar *filename,
				      const gchar *password);
static gchar *create_password_mail_subject(const gchar *subject,
					   const gchar *date,
					   const gchar *filename,
					   const gchar *password);
static gchar *create_password_mail_body(const gchar *subject,
					const gchar *date,
					const gchar *filename,
					const gchar *password);

static void compose_created_cb(GObject *obj, gpointer compose);
static void compose_destroy_cb(GObject *obj, gpointer compose);
static gboolean compose_send_cb(GObject *obj, gpointer compose,
				gint compose_mode, gint send_mode,
				const gchar *msg_file, GSList *to_list);
static void compose_toolbar_changed_cb(GObject *obj, gpointer compose);
static void compose_attach_changed_cb(GObject *obj, gpointer compose);

static void send_encryption_clicked(GtkWidget *widget, gpointer data);

static void autoenc_setting(void);

static gulong autoenc_app_exit_handler_id = 0;

static gpointer autoenc_compose = NULL;
static MsgInfo *sent_msginfo = NULL;


void plugin_load(void)
{
	debug_print("autoenc plug-in loaded!\n");

	syl_init_gettext(GETTEXT_PACKAGE, LOCALEDIR);

	syl_plugin_add_menuitem("/Configuration", NULL, NULL, NULL);
	syl_plugin_add_menuitem("/Configuration", _("Configure automatic attachment encryption"), autoenc_setting, NULL);

	g_signal_connect_after(syl_app_get(), "init-done", G_CALLBACK(init_done_cb), NULL);
	autoenc_app_exit_handler_id =
		g_signal_connect(syl_app_get(), "app-exit", G_CALLBACK(app_exit_cb), NULL);
	syl_plugin_signal_connect("compose-created",
				  G_CALLBACK(compose_created_cb), NULL);
	syl_plugin_signal_connect("compose-destroy",
				  G_CALLBACK(compose_destroy_cb), NULL);
	syl_plugin_signal_connect("compose-send",
				  G_CALLBACK(compose_send_cb), NULL);
	syl_plugin_signal_connect("compose-toolbar-changed",
				  G_CALLBACK(compose_toolbar_changed_cb), NULL);
	syl_plugin_signal_connect("compose-attach-changed",
				  G_CALLBACK(compose_attach_changed_cb), NULL);

	/* load config */
	read_config();

	if (is_dir_exist(get_autoenc_tmp_dir())) {
		remove_all_files(get_autoenc_tmp_dir());
	}

	debug_print("autoenc plug-in loading done\n");
}

void plugin_unload(void)
{
	debug_print("autoenc plug-in unloaded!\n");
	g_signal_handler_disconnect(syl_app_get(), autoenc_app_exit_handler_id);
}

SylPluginInfo *plugin_info(void)
{
	return &info;
}

gint plugin_interface_version(void)
{
	return SYL_PLUGIN_INTERFACE_VERSION;
}

static void init_done_cb(GObject *obj, gpointer data)
{
	debug_print("autoenc: app init done\n");
}

static void app_exit_cb(GObject *obj, gpointer data)
{
	debug_print("autoenc: app_exit_cb: removing all temporary files\n");

	if (is_dir_exist(get_autoenc_tmp_dir())) {
		remove_all_files(get_autoenc_tmp_dir());
	}
}


static const gchar *get_autoenc_tmp_dir(void)
{
	static gchar *path = NULL;

	if (!path) {
		path = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, "autoenctmp", NULL);
	}

	return path;
}

#ifdef G_OS_WIN32
static gchar *get_7z_path_entry(HKEY root_hkey, LPWSTR name)
{
	HKEY hkey;
	DWORD size, type;
	LPWSTR wpath;
	gchar *path;

	debug_print("get_7z_path_entry: read %s/Software/7-Zip/%ls\n", root_hkey == HKEY_CURRENT_USER ? "HKCU" : "HKLM", name);

	if (RegOpenKeyExW(root_hkey, L"Software\\7-Zip", 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
		return NULL;
	}

	if (RegQueryValueExW(hkey, name, 0, &type, 0, &size) != ERROR_SUCCESS) {
		RegCloseKey(hkey);
		return NULL;
	}
	if (type != REG_SZ) {
		RegCloseKey(hkey);
		return NULL;
	}
	++size;
	wpath = g_malloc(size);
	if (RegQueryValueExW(hkey, name, 0, &type, (LPBYTE)wpath, &size) != ERROR_SUCCESS) {
		RegCloseKey(hkey);
		return NULL;
	}
	RegCloseKey(hkey);

	path = g_utf16_to_utf8(wpath, -1, NULL, NULL, NULL);
	g_free(wpath);

	debug_print("get_7z_path_entry: %s\n", path);

	return path;
}

static gchar *get_7z_path(void)
{
	static gchar *path = NULL;
	gchar *filename;

	if (path) {
		return path;
	}

	path = get_7z_path_entry(HKEY_CURRENT_USER, L"Path");
	if (path) {
		filename = g_strconcat(path, G_DIR_SEPARATOR_S, "7z.exe", NULL);
		if (is_file_exist(filename)) {
			debug_print("get_7z_path: %s found.\n", filename);
			g_free(filename);
			return path;
		}
		g_free(filename);
		g_free(path);
		path = NULL;
	}

	path = get_7z_path_entry(HKEY_LOCAL_MACHINE, L"Path");
	if (path) {
		filename = g_strconcat(path, G_DIR_SEPARATOR_S, "7z.exe", NULL);
		if (is_file_exist(filename)) {
			debug_print("get_7z_path: %s found.\n", filename);
			g_free(filename);
			return path;
		}
		g_free(filename);
		g_free(path);
		path = NULL;
	}

	debug_print("get_7z_path: 7-Zip not found.\n");
	return NULL;
}
#else
static gchar *get_7z_path(void)
{
	return NULL;
}
#endif

static void read_config(void)
{
	gchar *path;
	gboolean initial = FALSE;

	debug_print("autoenc: read_config\n");
	path = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, "autoencrc", NULL);
	if (!is_file_exist(path)) {
		initial = TRUE;
		prefs_set_default(param);
	} else {
		prefs_read_config(param, "AutoEncrypt", path, NULL);
	}

	if (!config.autoenc_template_subject) {
		config.autoenc_template_subject =
			g_strdup(_("Password of encrypted file"));
	}
	if (!config.autoenc_template_body) {
		config.autoenc_template_body =
			g_strdup(_("Subject: %s\\n"
				   "Date: %d\\n"
				   "The password of the encrypted file attached in the above mail is as follows:\\n"
				   "\\n"
				   "File name: %z\\n"
				   "Password: %p"));
	}

	if (initial) {
		write_config();
	}

	g_free(path);
}

static void write_config(void)
{
	debug_print("autoenc: write_config\n");
	prefs_write_config(param, "AutoEncrypt", "autoencrc");
}

static gchar *generate_password(void)
{
	SMD5 *md5;
	time_t t;
	gchar date_str[15];
	const gchar *hostname;
	guint32 salt;
	gchar *b64;

	time(&t);
	strftime(date_str, sizeof(date_str), "%Y%m%d%H%M%S", localtime(&t));

	hostname = get_domain_name();

	salt = g_random_int();

	md5 = s_gnet_md5_new_incremental();
	s_gnet_md5_update(md5, (guchar *)date_str, strlen(date_str));
	s_gnet_md5_update(md5, (const guchar *)hostname, strlen(hostname));
	s_gnet_md5_update(md5, (guchar *)&salt, sizeof(salt));
	s_gnet_md5_final(md5);

	b64 = g_malloc(S_GNET_MD5_HASH_LENGTH * 2);
	base64_encode(b64, (guchar *)s_gnet_md5_get_digest(md5), S_GNET_MD5_HASH_LENGTH);
	debug_print("generate_password: b64(%s %s %u) = %s\n", date_str, hostname, salt, b64);
	b64[12] = '\0';
	debug_print("generate_password: password = %s\n", b64);

	s_gnet_md5_delete(md5);

	return b64;
}

static gchar *generate_filename(void)
{
	time_t t;
	gchar filename[32];

	time(&t);
	strftime(filename, sizeof(filename), "%Y%m%d%H%M%S-encrypt.zip", localtime(&t));

	return g_strdup(filename);
}

static void change_button_sensitive(gpointer compose, GtkWidget *toolbar)
{
	GSList *alist;
	GtkWidget *send_enc_btn;
	GtkWidget *send_btn;
	GtkWidget *send_later_btn;
	gboolean sensitive;

	if (!toolbar) {
		return;
	}

	send_enc_btn = g_object_get_data(G_OBJECT(toolbar), "send-enc-button");
	send_btn = g_object_get_data(G_OBJECT(toolbar), "se-send-button");
	send_later_btn = g_object_get_data(G_OBJECT(toolbar), "se-send-later-button");

	alist = syl_plugin_get_attach_list(compose);

	if (alist) {
		debug_print("autoenc: enable button\n");
		sensitive = TRUE;
	} else {
		debug_print("autoenc: disable button\n");
		sensitive = FALSE;
	}

	if (send_enc_btn) {
		gtk_widget_set_sensitive(send_enc_btn, sensitive);
	}
	if (config.force_encryption) {
		sensitive = !sensitive;
	} else {
		sensitive = TRUE;
	}
	if (send_btn) {
		gtk_widget_set_sensitive(send_btn, sensitive);
	}
	if (send_later_btn) {
		gtk_widget_set_sensitive(send_later_btn, sensitive);
	}

	g_slist_free(alist);
}

static void add_button(gpointer compose)
{
	GtkWidget *toolbar;
	PrefsCommon *prefs;
	gint n = 0;
	gint n_s = -1, n_sl = -1;
	GtkToolItem *item;
	GtkWidget *icon;
	GdkPixbuf *pixbuf;

	if (!config.enable_autoenc) {
		debug_print("autoenc: autoenc is disabled\n");
		return;
	}

	toolbar = syl_plugin_compose_get_toolbar(compose);
	//n = gtk_toolbar_get_n_items(GTK_TOOLBAR(toolbar));

	prefs = prefs_common_get();
	if (prefs->compose_toolbar_setting) {
		gint i;
		gchar **namev;

		namev = g_strsplit(prefs->compose_toolbar_setting, ",", -1);
		for (i = 0; namev[i] != NULL; i++) {
			if (!strcmp(namev[i], "send")) {
				debug_print("send pos: %d\n", i);
				n_s = i;
				n = i + 1;
			} else if (!strcmp(namev[i], "send-later")) {
				debug_print("send-later pos: %d\n", i);
				n_sl = i;
			}
		}
		g_strfreev(namev);
	} else {
		/* send,send-later,draft,... */
		n_s = 0;
		n_sl = 1;
		n = 1;
	}

	if (n_s >= 0) {
		item = gtk_toolbar_get_nth_item(GTK_TOOLBAR(toolbar), n_s);
		if (item) {
			g_object_set_data(G_OBJECT(toolbar), "se-send-button", item);
		}
	}
	if (n_sl >= 0) {
		item = gtk_toolbar_get_nth_item(GTK_TOOLBAR(toolbar), n_sl);
		if (item) {
			g_object_set_data(G_OBJECT(toolbar), "se-send-later-button", item);
		}
	}

	//icon = stock_pixbuf_widget_for_toolbar(STOCK_PIXMAP_MAIL_SEND);
	pixbuf = gdk_pixbuf_new_from_inline(sizeof(send_enc), send_enc,
					    FALSE, NULL);
	icon = gtk_image_new_from_pixbuf(pixbuf);
	item = gtk_tool_button_new(icon, _("Send with encryption"));
	gtk_tool_item_set_is_important(item, TRUE);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar), item, n);
	//gtk_widget_show_all(GTK_WIDGET(toolbar));
	gtk_widget_show_all(GTK_WIDGET(item));

	g_object_set_data(G_OBJECT(toolbar), "send-enc-button", item);

	g_signal_connect(G_OBJECT(item), "clicked",
			 G_CALLBACK(send_encryption_clicked), compose);

	change_button_sensitive(compose, toolbar);
}

static void send_with_encryption(gpointer compose)
{
	GSList *alist, *cur;
	GHashTable *hash;
	SylPluginAttachInfo *ainfo;
	gboolean duplicated = FALSE;
	GtkWidget *dialog;
	gchar *password;
	const gchar *tmp_path;
	const gchar *arc_path;
	gchar *zip_path;
	gchar *filename;
	GString *cmdline;
	gint ret;
	gchar *orig_to;
	gchar *orig_cc;
	gchar *orig_bcc;
	gchar *orig_replyto;
	gchar *orig_subject;
	gchar *subject;
	gchar *body;
	gchar send_date[80];
	GtkWidget *textview;
	GtkTextBuffer *buffer;
	GtkTextMark *mark;
	GtkTextIter iter;

	/* Check attachments */
	alist = syl_plugin_get_attach_list(compose);
	if (!alist) {
		syl_plugin_alertpanel_message(_("No attachment"), _("There is no attachment. Please attach files before sending."), 3);
		return;
	}
	hash = g_hash_table_new(str_case_hash, str_case_equal);
	for (cur = alist; cur != NULL; cur = cur->next) {
		const gchar *base;
		ainfo = (SylPluginAttachInfo *)cur->data;
		debug_print("attach: file: %s (%s) name: %s\n", ainfo->file, ainfo->content_type, ainfo->name);
		base = g_basename(ainfo->file);
		if (g_hash_table_lookup(hash, base)) {
			duplicated = TRUE;
			break;
		} else {
			g_hash_table_insert(hash, (gpointer)base, (gpointer)base);
		}
	}
	g_hash_table_destroy(hash);
	if (duplicated) {
		syl_plugin_alertpanel_message(_("Duplicate filename"), _("There are duplicate filenames. Multiple files with same name cannot be attached."), 3);
		return;
	}

	/* Get recipients */
	orig_to = syl_plugin_compose_entry_get_text(compose, 0);
	orig_cc = syl_plugin_compose_entry_get_text(compose, 1);
	orig_bcc = syl_plugin_compose_entry_get_text(compose, 2);
	orig_replyto = syl_plugin_compose_entry_get_text(compose, 3);
	orig_subject = syl_plugin_compose_entry_get_text(compose, 4);
	if (orig_to) g_strstrip(orig_to);
	if (orig_cc) g_strstrip(orig_cc);
	if (orig_bcc) g_strstrip(orig_bcc);

	if ((!orig_to || *orig_to == '\0') &&
	    (!orig_cc || *orig_cc == '\0') &&
	    (!orig_bcc || *orig_bcc == '\0')) {
		syl_plugin_alertpanel_message(_("No recipients"), _("Recipient is not specified."), 3);
		g_free(orig_subject);
		g_free(orig_replyto);
		g_free(orig_bcc);
		g_free(orig_cc);
		g_free(orig_to);
		return;
	}

	/* Show processing dialog */
	dialog = autoenc_processing_dialog_create();

	/* Generate password */
	password = generate_password();

	/* Generate encrypted zip */
	filename = generate_filename();
	tmp_path = get_autoenc_tmp_dir();
	if (!is_dir_exist(tmp_path)) {
		make_dir(tmp_path);
	}
	arc_path = get_7z_path();
	zip_path = g_strconcat(tmp_path, G_DIR_SEPARATOR_S,
			       filename, NULL);
	cmdline = g_string_new("");
	if (arc_path) {
		g_string_append_printf(cmdline, "\"%s\\7z\" a -y ", arc_path);
	} else {
		g_string_append(cmdline, "7z a -y ");
	}
	g_string_append(cmdline, "-p");
	g_string_append(cmdline, password);
	g_string_append(cmdline, " ");
	g_string_append_printf(cmdline, "\"%s\"", zip_path);
	for (cur = alist; cur != NULL; cur = cur->next) {
		ainfo = (SylPluginAttachInfo *)cur->data;
		g_string_append(cmdline, " ");
		g_string_append_printf(cmdline, "\"%s\"", ainfo->file);
	}
	debug_print("cmdline: %s\n", cmdline->str);
	ret = execute_command_line_async_wait(cmdline->str);

	/* Close processing dialog */
	gtk_widget_destroy(dialog);

	// check if zip was really created
	if (ret != 0 || !is_file_exist(zip_path) || get_file_size(zip_path) <= 0) {
		gchar message[256];

		if (ret < 0) {
			g_snprintf(message, sizeof(message), _("Error occurred while creating encrypted zip file.\n\n7z command could not be executed. Please check if 7-Zip is correctly installed."));
		} else if (ret > 0) {
			g_snprintf(message, sizeof(message), _("Error occurred while creating encrypted zip file.\n\n7z command returned error (%d)"), ret);
		} else {
			g_snprintf(message, sizeof(message), _("Encrypted zip file could not be created."));
		}
		syl_plugin_alertpanel_message(_("Encrypted zip file creation error"), message, 3);
		g_string_free(cmdline, TRUE);
		g_free(zip_path);
		g_free(filename);
		g_free(password);
		g_free(orig_subject);
		g_free(orig_replyto);
		g_free(orig_bcc);
		g_free(orig_cc);
		g_free(orig_to);
		g_slist_free(alist);
		return;
	}
	g_string_free(cmdline, TRUE);
	g_slist_free(alist);

	/* Replace attachments */
	syl_plugin_compose_attach_remove_all(compose);
	syl_plugin_compose_attach_append(compose, zip_path, filename,
					 "application/zip");

	/* Send */
	get_rfc822_date(send_date, sizeof(send_date));
	autoenc_compose = compose;
	ret = syl_plugin_compose_send(compose, TRUE);
	autoenc_compose = NULL;
	if (ret != 0) {
		if (sent_msginfo) {
			g_unlink(sent_msginfo->file_path);
			procmsg_msginfo_free(sent_msginfo);
			sent_msginfo = NULL;
		}
		g_free(zip_path);
		g_free(filename);
		g_free(password);
		g_free(orig_subject);
		g_free(orig_replyto);
		g_free(orig_bcc);
		g_free(orig_cc);
		g_free(orig_to);
		return;
	}

	/* Create password mail */
	subject = create_password_mail_subject(orig_subject, send_date, filename, password);

	/* sent_msginfo is generated in compose_send_cb() callback */
	if (sent_msginfo) {
		body = replace_template_string(config.autoenc_template_body,
					       orig_subject, send_date, filename, password);
		compose = syl_plugin_compose_reply(sent_msginfo, NULL, 1, body);
		g_unlink(sent_msginfo->file_path);
		procmsg_msginfo_free(sent_msginfo);
		sent_msginfo = NULL;

		textview = syl_plugin_compose_get_textview(compose);
		buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
		mark = gtk_text_buffer_get_insert(buffer);
		gtk_text_buffer_get_iter_at_mark(buffer, &iter, mark);
		gtk_text_buffer_insert(buffer, &iter, body, -1);
		gtk_text_buffer_insert(buffer, &iter, "\n", 1);
	} else {
		body = create_password_mail_body(orig_subject, send_date, filename, password);
		compose = syl_plugin_compose_new(NULL, NULL, body, NULL);
	}
	debug_print("%s\n", body);

	syl_plugin_compose_entry_set(compose, orig_to, 0);
	syl_plugin_compose_entry_set(compose, orig_cc, 1);
	if (orig_bcc && *orig_bcc != '\0')
		syl_plugin_compose_entry_set(compose, orig_bcc, 2);
	if (orig_replyto && *orig_replyto != '\0')
		syl_plugin_compose_entry_set(compose, orig_replyto, 3);
	syl_plugin_compose_entry_set(compose, subject, 4);

	/* Cleanup */
	g_free(body);
	g_free(subject);
	g_free(zip_path);
	g_free(filename);
	g_free(password);
	g_free(orig_subject);
	g_free(orig_replyto);
	g_free(orig_bcc);
	g_free(orig_cc);
	g_free(orig_to);
}

static GtkWidget *autoenc_processing_dialog_create(void)
{
	GtkWidget *dialog;
	GtkWidget *hbox;
	GtkWidget *spinner;
	GtkWidget *label;

	dialog = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_container_set_border_width(GTK_CONTAINER(dialog), 16);
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_title(GTK_WINDOW(dialog), _("Encrypting attachments"));
	gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
	gtk_window_set_policy(GTK_WINDOW(dialog), FALSE, FALSE, FALSE);
	syl_plugin_manage_window_set_transient(GTK_WINDOW(dialog));
	//g_signal_connect(G_OBJECT(dialog), "delete_event", G_CALLBACK(gtk_true), NULL);

	hbox = gtk_hbox_new(FALSE, 12);
	gtk_container_add(GTK_CONTAINER(dialog), hbox);
	gtk_widget_show(hbox);

	spinner = gtk_spinner_new();
	gtk_widget_set_size_request(spinner, 16, 16);
	gtk_box_pack_start(GTK_BOX(hbox), spinner, FALSE, FALSE, 0);
	gtk_widget_show(spinner);

	label = gtk_label_new(_("Encrypting attachments..."));
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	gtk_widget_show(dialog);

	gtk_spinner_start(GTK_SPINNER(spinner));

	return dialog;
}

static gchar *escape_newlines(const gchar *str)
{
	gchar *newstr;
	const gchar *s;
	gchar *p;

	g_return_val_if_fail(str != NULL, NULL);

	newstr = g_malloc(strlen(str) * 2 + 1);
	s = str;
	p = newstr;

	while (*s != '\0') {
		if (*s == '\n') {
			s++;
			*p++ = '\\';
			*p++ = 'n';
		} else {
			*p++ = *s++;
		}
	}

	*p = '\0';
	return newstr;
}

static gchar *unescape_newlines(const gchar *str)
{
	gchar *newstr;
	const gchar *s;
	gchar *p;

	g_return_val_if_fail(str != NULL, NULL);

	newstr = g_malloc(strlen(str) + 1);
	s = str;
	p = newstr;

	while (*s != '\0') {
		if (*s == '\\' && *(s + 1) == 'n') {
			s += 2;
			*p++ = '\n';
		} else {
			*p++ = *s++;
		}
	}

	*p = '\0';
	return newstr;
}

static gchar *replace_template_string(const gchar *template,
				      const gchar *subject,
				      const gchar *date,
				      const gchar *filename,
				      const gchar *password)
{
	GString *body;
	const gchar *s = template;

	body = g_string_new("");

	while (*s != '\0') {
		if (*s == '%') {
			switch (*(s + 1)) {
			case 's':
				g_string_append(body, subject);
				s += 2;
				break;
			case 'd':
				g_string_append(body, date);
				s += 2;
				break;
			case 'z':
				g_string_append(body, filename);
				s += 2;
				break;
			case 'p':
				g_string_append(body, password);
				s += 2;
				break;
			case '%':
				s++;
				g_string_append_c(body, *s++);
				break;
			default:
				s++;
				break;
			}
		} else if (*s == '\\' && *(s + 1) == 'n') {
			s += 2;
			g_string_append_c(body, '\n');
		} else {
			g_string_append_c(body, *s++);
		}
	}

	return g_string_free(body, FALSE);
}

static gchar *create_password_mail_subject(const gchar *subject,
					   const gchar *date,
					   const gchar *filename,
					   const gchar *password)
{
	gchar *subj;

	subj = replace_template_string(config.autoenc_template_subject,
				       subject, date, filename, password);

	return subj;
}

static gchar *create_password_mail_body(const gchar *subject,
					const gchar *date,
					const gchar *filename,
					const gchar *password)
{
	gchar *body;
	gchar *esc_body;
	gchar *mailto;

	body = replace_template_string(config.autoenc_template_body,
				       subject, date, filename, password);
	esc_body = g_uri_escape_string(body, NULL, TRUE);
	mailto = g_strconcat("?body=", esc_body, NULL);
	g_free(esc_body);
	g_free(body);

	return mailto;
}

static void autoenc_settings_dialog(void)
{
	GtkWidget *dialog;
	GtkWidget *content_area;
	GtkWidget *vbox;

	GtkWidget *enable_chkbtn;
	GtkWidget *force_chkbtn;
	GtkWidget *frame;
	GtkWidget *vbox2;
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *subject_entry;
	GtkWidget *scrolledwin;
	GtkWidget *body_textview;
	GtkTextBuffer *text_buffer;
	GtkTextIter start, end;

	gchar *body_text;
	gint result;

	dialog = gtk_dialog_new_with_buttons
		(_("Automatic Encryption Settings"), NULL, 0,
		 GTK_STOCK_OK, GTK_RESPONSE_OK,
		 GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
		 NULL);
	gtk_window_set_policy(GTK_WINDOW(dialog), FALSE, TRUE, FALSE);
	gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);

	vbox = gtk_vbox_new(FALSE, 8);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
	content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	gtk_box_pack_start(GTK_BOX(content_area), vbox,
			   TRUE, TRUE, 0);

	enable_chkbtn = gtk_check_button_new_with_label
		(_("Enable automatic attachment encryption"));
	gtk_box_pack_start(GTK_BOX(vbox), enable_chkbtn, FALSE, FALSE, 0);

	force_chkbtn = gtk_check_button_new_with_label
		(_("Enforce 'Send with encryption' when there are attachments"));
	gtk_box_pack_start(GTK_BOX(vbox), force_chkbtn, FALSE, FALSE, 0);

	frame = gtk_frame_new(_("Password Mail Template"));
	gtk_box_pack_start(GTK_BOX(vbox), frame, TRUE, TRUE, 0);

	vbox2 = gtk_vbox_new(FALSE, 8);
	gtk_container_set_border_width(GTK_CONTAINER(vbox2), 8);
	gtk_container_add(GTK_CONTAINER(frame), vbox2);

	hbox = gtk_hbox_new(FALSE, 8);
	gtk_box_pack_start(GTK_BOX(vbox2), hbox, FALSE, FALSE, 0);

	label = gtk_label_new(_("Subject:"));
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	subject_entry = gtk_entry_new();
	gtk_widget_set_size_request(subject_entry, 120, -1);
	gtk_box_pack_start(GTK_BOX(hbox), subject_entry, TRUE, TRUE, 0);

	label = gtk_label_new(_("Body:"));
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_box_pack_start(GTK_BOX(vbox2), label, FALSE, FALSE, 0);

	scrolledwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_box_pack_start(GTK_BOX(vbox2), scrolledwin, TRUE, TRUE, 0);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwin),
				       GTK_SHADOW_IN);

	body_textview = gtk_text_view_new();
	gtk_widget_set_size_request(body_textview, 420, 150);
	gtk_container_add(GTK_CONTAINER(scrolledwin), body_textview);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(body_textview), TRUE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(body_textview), GTK_WRAP_WORD);
	gtk_text_view_set_left_margin(GTK_TEXT_VIEW(body_textview), 4);
	gtk_text_view_set_right_margin(GTK_TEXT_VIEW(body_textview), 4);
	text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(body_textview));

	/* set configuration data */
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(enable_chkbtn),
				     config.enable_autoenc);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(force_chkbtn),
				     config.force_encryption);
	gtk_entry_set_text(GTK_ENTRY(subject_entry), config.autoenc_template_subject);
	body_text = unescape_newlines(config.autoenc_template_body);
	gtk_text_buffer_set_text(text_buffer, body_text, -1);
	g_free(body_text);

	gtk_widget_show_all(dialog);
	syl_plugin_manage_window_set_transient(GTK_WINDOW(dialog));

	syl_plugin_inc_lock();
	result = gtk_dialog_run(GTK_DIALOG(dialog));
	if (result == GTK_RESPONSE_OK) {
		debug_print("autoenc_setting: ok clicked\n");

		config.enable_autoenc = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(enable_chkbtn));
		config.force_encryption = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(force_chkbtn));

		g_free(config.autoenc_template_subject);
		config.autoenc_template_subject = gtk_editable_get_chars(GTK_EDITABLE(subject_entry), 0, -1);
		gtk_text_buffer_get_start_iter(text_buffer, &start);
		gtk_text_buffer_get_end_iter(text_buffer, &end);
		body_text = gtk_text_buffer_get_text(text_buffer, &start, &end, FALSE);
		g_free(config.autoenc_template_body);
		config.autoenc_template_body = escape_newlines(body_text);
		g_free(body_text);

		write_config();
	}
	syl_plugin_inc_unlock();

	gtk_widget_destroy(dialog);
}


/* Callback functions */

static void compose_created_cb(GObject *obj, gpointer compose)
{
	debug_print("autoenc: %p: compose created (%p)\n", obj, compose);

	add_button(compose);
}

static void compose_destroy_cb(GObject *obj, gpointer compose)
{
	debug_print("autoenc: %p: compose will be destroyed (%p)\n", obj, compose);
}

static gboolean compose_send_cb(GObject *obj, gpointer compose,
				gint compose_mode, gint send_mode,
				const gchar *msg_file, GSList *to_list)
{
	MsgFlags flags = {0, 0};

	debug_print("autoenc: %p: composed message will be sent (%p)\n", obj, compose);
	debug_print("autoenc: compose_mode: %d, send_mode: %d, file: %s\n",
		    compose_mode, send_mode, msg_file);

	if (autoenc_compose == compose) {
		debug_print("autoenc: this Compose object is in auto-encryption mode.\n");
	} else {
		return FALSE;
	}

	sent_msginfo = procheader_parse_file(msg_file, flags, FALSE);
	if (!sent_msginfo) {
		debug_print("autoenc: compose_send_cb: couldn't get message info of sent message\n");
	} else {
		sent_msginfo->file_path = get_tmp_file();
		copy_file(msg_file, sent_msginfo->file_path, FALSE);
	}

	return FALSE; /* return TRUE to cancel sending */
}

static void compose_toolbar_changed_cb(GObject *obj, gpointer compose)
{
	debug_print("compose_toolbar_changed_cb\n");

	add_button(compose);
}

static void compose_attach_changed_cb(GObject *obj, gpointer compose)
{
	GtkWidget *toolbar;

	debug_print("compose_attach_changed_cb\n");

	toolbar = syl_plugin_compose_get_toolbar(compose);
	change_button_sensitive(compose, toolbar);
}

static void send_encryption_clicked(GtkWidget *widget, gpointer data)
{
	debug_print("send_encryption_clicked\n");

	send_with_encryption(data);
}

static void autoenc_setting(void)
{
	autoenc_settings_dialog();
}
