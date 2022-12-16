#include "gmime/gmime-application-pkcs7-mime.h"
#include "gmime/gmime-message.h"
#include "gmime/gmime-multipart-encrypted.h"
#include "gmime/gmime-multipart-signed.h"
#include "gmime/gmime-object.h"
#include "gmime/gmime-part.h"
#include "gmime/gmime-stream-mem.h"
#include "gmime/gmime-stream.h"
#include <galore-sq-context.h>
#include <glib.h>
#include <gmime/gmime.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static GMimeCryptoContext *new_ctx();
static void write_message_to_screen (GMimeObject *obj);
static GMimeMessage *make_signed();
static GMimeMessage *make_signed_detach();
static GMimeMessage *make_encrypted();
static void import_keys();
static void export_keys();

#define USER "testi@test.com"
#define DATADIR "./"

static void
write_message_to_screen (GMimeObject *obj)
{
	GMimeStream *stream;
	
	/* create a new stream for writing to stdout */
	stream = g_mime_stream_pipe_new (STDOUT_FILENO);
	g_mime_stream_pipe_set_owner ((GMimeStreamPipe *) stream, FALSE);
	
	/* write the message to the stream */
	g_mime_object_write_to_stream (obj, NULL, stream);
	
	/* flush the stream (kinda like fflush() in libc's stdio) */
	g_mime_stream_flush (stream);
	
	/* free the output stream */
	g_object_unref (stream);
}

static GMimeMessage *make_signed() {
	GMimeMessage *message;
	GMimeTextPart *body;
	GError *err;

	message = g_mime_message_new (TRUE);

	g_mime_message_add_mailbox (message, GMIME_ADDRESS_TYPE_FROM, "Testi McTest", "joey@friends.com");
	g_mime_message_add_mailbox (message, GMIME_ADDRESS_TYPE_TO, "Alice", "alice@wonderland.com");
	g_mime_message_set_subject (message, "How you doin?", NULL);

	body = g_mime_text_part_new_with_subtype ("plain");
	g_mime_text_part_set_text (body, "Hey Alice,\n\n"
			"What are you up to this weekend? Monica is throwing one of her parties on\n"
			"Saturday and I was hoping you could make it.\n\n"
			"Will you be my +1?\n\n"
			"-- Joey\n");

	gboolean res = g_mime_part_openpgp_sign((GMimePart *)body, USER, &err);
	if (!res || err != NULL) {
		fprintf (stderr, "signing failed: %s\n", err->message);
		return NULL;
	}
	g_mime_message_set_mime_part (message, (GMimeObject *) body);
	g_object_unref (body);
	return message;
}

static GMimeMessage *make_signed_detach(GMimeCryptoContext *ctx) {
	GMimeMessage *message;
	GMimeTextPart *body;
	GError *err;
	GMimeMultipartSigned *mps;

	message = g_mime_message_new (TRUE);

	g_mime_message_add_mailbox (message, GMIME_ADDRESS_TYPE_FROM, "Testi McTest", "joey@friends.com");
	g_mime_message_add_mailbox (message, GMIME_ADDRESS_TYPE_TO, "Alice", "alice@wonderland.com");
	g_mime_message_set_subject (message, "How you doin?", NULL);

	body = g_mime_text_part_new_with_subtype ("plain");
	g_mime_text_part_set_text (body, "Hey Alice,\n\n"
			"What are you up to this weekend? Monica is throwing one of her parties on\n"
			"Saturday and I was hoping you could make it.\n\n"
			"Will you be my +1?\n\n"
			"-- Joey\n");

	mps = g_mime_multipart_signed_sign(ctx, (GMimeObject *) body, USER, &err);
	if (err != NULL) {
		fprintf (stderr, "signing failed: %s\n", err->message);
		return NULL;
	}
	g_mime_message_set_mime_part (message, (GMimeObject *) mps);
	// g_object_unref (body);
	g_object_unref (mps);
	return message;
}

static GMimeMessage *make_encrypted(GMimeCryptoContext *ctx) {
	GMimeMessage *message;
	GMimeTextPart *body;
	GError *err;
	GMimeMultipartEncrypted *mpe;
	GPtrArray *recipients;

	message = g_mime_message_new (TRUE);

	g_mime_message_add_mailbox (message, GMIME_ADDRESS_TYPE_FROM, "Testi McTest", "joey@friends.com");
	g_mime_message_add_mailbox (message, GMIME_ADDRESS_TYPE_TO, "Alice", "alice@wonderland.com");
	g_mime_message_set_subject (message, "How you doin?", NULL);

	body = g_mime_text_part_new_with_subtype ("plain");
	g_mime_text_part_set_text (body, "Hey Alice,\n\n"
			"What are you up to this weekend? Monica is throwing one of her parties on\n"
			"Saturday and I was hoping you could make it.\n\n"
			"Will you be my +1?\n\n"
			"-- Joey\n");

	recipients = g_ptr_array_new ();
	g_ptr_array_add (recipients, "<testi@test.com>");

	mpe = g_mime_multipart_encrypted_encrypt(ctx, (GMimeObject *) body, TRUE, USER,
			GMIME_ENCRYPT_NONE, recipients, &err);
	// g_object_unref (body);
	g_ptr_array_unref(recipients);
	if (err != NULL) {
		fprintf (stderr, "encrypting failed: %s\n", err->message);
		return NULL;
	}

	g_mime_message_set_mime_part (message, (GMimeObject *) mpe);
	// g_object_unref (mpe);
	return message;
}

static void show_status(GMimeSignatureStatus status) {
	const char *str;
	switch (status) {
        case GMIME_SIGNATURE_STATUS_VALID:
			str = "Valid";
          break;
        case GMIME_SIGNATURE_STATUS_GREEN:
			str = "Green";
          break;
        case GMIME_SIGNATURE_STATUS_RED:
			str = "Red";
          break;
        case GMIME_SIGNATURE_STATUS_KEY_REVOKED:
			str = "Revoked";
          break;
        case GMIME_SIGNATURE_STATUS_KEY_EXPIRED:
			str = "Key Expired";
          break;
        case GMIME_SIGNATURE_STATUS_SIG_EXPIRED:
			str = "Sig Expried";
          break;
        case GMIME_SIGNATURE_STATUS_KEY_MISSING:
			str = "Key Missing";
          break;
        case GMIME_SIGNATURE_STATUS_CRL_MISSING:
			str = "CRL Missing";
          break;
        case GMIME_SIGNATURE_STATUS_CRL_TOO_OLD:
			str = "CRL TOO OLD";
          break;
        case GMIME_SIGNATURE_STATUS_BAD_POLICY:
			str = "Bad policy";
          break;
        case GMIME_SIGNATURE_STATUS_SYS_ERROR:
			str = "Sys error";
          break;
        case GMIME_SIGNATURE_STATUS_TOFU_CONFLICT:
			str = "TOFU Conflict";
          break;
        }
	printf("Signature was: %s\n", str);
}

static void
decrypt_foreach_callback (GMimeObject *parent, GMimeObject *part, gpointer user_data)
{
	if (GMIME_IS_MULTIPART_ENCRYPTED (part)) {
		GMimeMultipartEncrypted *mpe = (GMimeMultipartEncrypted *) part;
		GMimeDecryptResult *res;
		GError *err;
		GMimeObject *obj;
		int i;
		GMimeSignature *sig;
		
		if (!(obj = g_mime_multipart_encrypted_decrypt (mpe, 
						GMIME_DECRYPT_ENABLE_KEYSERVER_LOOKUPS, 
						NULL,
						&res,
						&err))) {
			fprintf (stderr, "Failed to decrypt encrypted part: %s\n", err->message);
			g_error_free (err);
		} else {
			write_message_to_screen(obj);

			for (i = 0; i < g_mime_signature_list_length (res->signatures); i++) {
				sig = g_mime_signature_list_get_signature (res->signatures, i);
				
				show_status(sig->status);
			}
			g_object_unref (res);
		}
	}
}

void decrypt_message(GMimeMessage *message) {
	if (message)
		g_mime_message_foreach (message, decrypt_foreach_callback, NULL);
}

static void
verify_foreach_callback (GMimeObject *parent, GMimeObject *part, gpointer user_data)
{
	if (GMIME_IS_MULTIPART_SIGNED (part)) {
		GMimeMultipartSigned *mps = (GMimeMultipartSigned *) part;
		GMimeSignatureList *signatures;
		GMimeSignature *sig;
		GError *err;
		int i;
		
		if (!(signatures = g_mime_multipart_signed_verify (mps, GMIME_VERIFY_NONE, &err))) {
			fprintf (stderr, "Failed to verify signed part: %s\n", err->message);
			g_error_free (err);
		} else {
			for (i = 0; i < g_mime_signature_list_length (signatures); i++) {
				sig = g_mime_signature_list_get_signature (signatures, i);
				
				show_status(sig->status);
			}
			g_object_unref (signatures);
		}
	}
}

static void
verify_signed_parts (GMimeMessage *message)
{
	if (message)
		g_mime_message_foreach (message, verify_foreach_callback, NULL);
}

static void import_keys(GMimeCryptoContext *ctx) {
	int ret;
	GError *err;
	GMimeStream *istream;
	char *keyfile;
	int fd;
	keyfile = g_build_filename (DATADIR, "testcertimport.pgp", NULL);

	if ((fd = open (keyfile, O_RDONLY, 0)) == -1) {
		fprintf(stderr, "open() failed: %s\n", g_strerror (errno));
	}

	istream = g_mime_stream_fs_new (fd);
	ret = g_mime_crypto_context_import_keys (ctx, istream, &err);
	g_object_unref (istream);

	if (ret <= 0) {
		printf("No keys new were imported\n");
	}

	if (err != NULL) {
		printf("Failed to import keys: %s\n", err->message);
	}
	printf("%d keys new were imported\n", ret);
}

static void export_keys_helper(GMimeCryptoContext *ctx, const char **keys) {
	int ret;
	GError *err;
	GMimeStream *mem = g_mime_stream_mem_new();
	GMimeStreamMem *memmem;

	ret = g_mime_crypto_context_export_keys(ctx, keys, mem, &err);
	g_mime_stream_flush((GMimeStream *)mem);

	if (ret <= 0) {
		printf("No keys found\n");
		return;
	}

	if (err != NULL) {
		printf("Failed to export keys: %s\n", err->message);
		return;
	}
	memmem = (GMimeStreamMem *) mem;
	printf("Number of keys: %d\n %.*s\n", ret, memmem->buffer->len, memmem->buffer->data);
	g_object_unref (mem);
}

static void export_keys(GMimeCryptoContext *ctx) {
	const char *keys[2];
	keys[0] = USER;
	keys[1] = NULL;
	export_keys_helper(ctx, keys);
}
static void export_keys_fail(GMimeCryptoContext *ctx) {
	const char *keys[2];
	keys[0] = "I'm not in your keyring!";
	keys[1] = NULL;
	export_keys_helper(ctx, keys);
}

static gboolean
request_passwd (GMimeCryptoContext *ctx, const char *user_id, const char *prompt, gboolean reprompt, GMimeStream *response, GError **err)
{
	printf("uid: %s\n", user_id);
	printf("prompt: %s\n", prompt);

	g_mime_stream_write_string (response, "nopass");
	g_mime_stream_flush(response);
	
	return TRUE;
}

static const char *path = DATADIR "testring.pgp"; // default path

static GMimeCryptoContext *new_ctx() {
	GMimeCryptoContext *ctx = galore_sq_context_new(path);
	g_mime_crypto_context_set_request_password (ctx, request_passwd);
	return ctx;
}

static void run_context(const char *new_path) {
	path = new_path;
	g_mime_crypto_context_register ("application/x-pgp-signature", new_ctx);
	g_mime_crypto_context_register ("application/pgp-signature", new_ctx);
	g_mime_crypto_context_register ("application/x-pgp-encrypted", new_ctx);
	g_mime_crypto_context_register ("application/pgp-encrypted", new_ctx);
	g_mime_crypto_context_register ("application/pgp-keys", new_ctx);

	GMimeCryptoContext *ctx = new_ctx();

	GMimeMessage *signed_message = make_signed();
	verify_signed_parts(signed_message);
	g_object_unref (signed_message);

	GMimeMessage *detach_message = make_signed_detach(ctx);
	verify_signed_parts(detach_message);
	g_object_unref (signed_message);

	GMimeMessage *encrypted = make_encrypted(ctx);
	decrypt_message(encrypted);
	g_object_unref (signed_message);

	export_keys(ctx);
	export_keys_fail(ctx);
	import_keys(ctx);

	// importing the same key multiple times 
	// shouldn't do anything
	import_keys(ctx);
	import_keys(ctx);
	import_keys(ctx);
	import_keys(ctx);
	import_keys(ctx);

	g_object_unref (ctx);
}

int main (int argc, char **argv)
{
	/* init the gmime library */
	g_mime_init ();

	run_context(DATADIR "testring.pgp");
	// run_context(DATADIR "encrypted.pgp");
	
	return 0;
}
