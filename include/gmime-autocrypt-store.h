/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*  GMime
 *  Copyright (C) Per Odlund
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free
 *  Software Foundation, 51 Franklin Street, Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#ifndef __GMIME_AUTOCRYPT_STORE_H__
#define __GMIME_AUTOCRYPT_STORE_H__

#include <gmime/gmime-autocrypt.h>

G_BEGIN_DECLS

#define GMIME_TYPE_AUTOCRYPT_STORE            (g_mime_autocrypt_store_get_type ())
#define GMIME_AUTOCRYPT_STORE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GMIME_TYPE_AUTOCRYPT_STORE, GMimeAutocryptStore))
#define GMIME_AUTOCRYPT_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GMIME_TYPE_AUTOCRYPT_STORE, GMimeAutocryptStoreClass))
#define GMIME_IS_AUTOCRYPT_STORE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GMIME_TYPE_AUTOCRYPT_STORE))
#define GMIME_IS_AUTOCRYPT_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GMIME_TYPE_AUTOCRYPT_STORE))
#define GMIME_AUTOCRYPT_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GMIME_TYPE_AUTOCRYPT_STORE, GMimeAutocryptStoreClass))

typedef struct _GMimeAutocryptStore GMimeAutocryptStore;
typedef struct _GMimeAutocryptStoreClass GMimeAutocryptStoreClass;

struct _GMimeCryptoPolicy {
	GObject parent;
};

struct _GMimeAutocryptStoreClass {
	GObjectClass parent_class;
};

typedef enum {
	GMIME_AUTOCRYPT_RECOMMENDATION_DISABLE,
	GMIME_AUTOCRYPT_RECOMMENDATION_DISCOURAGE,
	GMIME_AUTOCRYPT_RECOMMENDATION_AVAILABLE,
	GMIME_AUTOCRYPT_RECOMMENDATION_ENCRYPT,
} GMimeEncryptionRecommendation;

GType g_mime_autocrypt_store_get_type (void);

void g_mime_autocrypt_setup(const char *path);

GMimeAutocryptStore *g_mime_autocrypt_store_connect (const char *path, const char *password,
		gboolean wildmode);

gboolean g_mime_autocrypt_store_update_private_key(GMimeAutocryptStore *store,
		GMimeCryptoPolicy *policy, const char account_mail, GError **err);

gboolean g_mime_autocrypt_store_update_last_seen(GMimeAutocryptStore *store, const char *account_mail,
		const char *peer_mail, GDateTime *effecive_date, GError **err);

gboolean g_mime_autocrypt_store_update_peer(GMimeAutocryptStore *store, const char *account_mail,
		const char *peer_mail, GBytes *key, GMimeAutocryptPrefer prefer, 
		gboolean gossip, GDateTime *effecive_date, GError **err);

GMimeEncryptionRecommendation g_mime_autocrypt_store_recomend(GMimeAutocryptStore *store, 
		const char *account_mail, const char *peer_mail,
		GMimeCryptoPolicy *policy, GMimeAutocryptPreferEncrypt *prefer); 

// GMimeEncryptionRecommendation g_mime_autocrypt_store_multi_recomend(GMimeAutocryptStore *store,
// 		const char *account_mail, GPtrArray *peers_mail, 
// 		GMimeCryptoPolicy *policy, GMimeAutocryptPreferEncrypt *prefer); 

GMimeAutocryptHeader *g_mime_autocrypt_store_get_header(GMimeAutocryptStore *store,
		const char *account_mail, GMimeCryptoPolicy *policy, 
		GMimeAutocryptPreferEncrypt *prefer, GError **err);

GMimeAutocryptHeader *g_mime_autocrypt_store_get_gossip_header(GMimeAutocryptStore *store,
		const char *account_mail, const char *peer,
		GMimeCryptoPolicy *policy, GError **err);

// TODO:
GMimeMessage *g_mime_autocrypt_store_setup_message(GMimeAutocryptStore *store, const char *account_mail,
		const char *from, const char *to, char **password, GError **err);

gboolean *g_mime_autocrypt_store_install_message(GMimeAutocryptStore *store, const char *account_mail,
		GMimeCryptoPolicy *policy, GMimeMessage *message, GError **err);

GMimeSignatureList *g_mime_autocrypt_store_decrypt(GMimeAutocryptStore *store, const char *account_mail,
		GMimeCryptoPolicy *policy, const char *session, GMimeStream *istream,
		GMimeStream *ostream, GError **err);

gboolean *g_mime_autocrypt_store_encrypt(GMimeAutocryptStore *store, const char *account_mail,
		GPtrArray *recipients, GMimeCryptoPolicy *policy, GMimeStream *istream,
		GMimeStream *ostream, GError **err);

// GMimeDecryptResult *g_mime_autocrypt_store_verify(GMimeAutocryptStore *store, const char *account_mail,
// 		GMimeCryptoPolicy *policy, GMimeStream *istream,
// 		GMimeStream *ostream, GError **err);

G_END_DECLS

#endif /* __GMIME_AUTOCRYPT_STORE_H__ */
