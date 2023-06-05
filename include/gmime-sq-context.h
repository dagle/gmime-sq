/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*  GMimeSq
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

#ifndef __GMIME_SQ_CONTEXT_H__
#define __GMIME_SQ_CONTEXT_H__

#include <gmime/gmime-crypto-context.h>

G_BEGIN_DECLS

#define GMIME_TYPE_SQ_CONTEXT            (gmime_sq_context_get_type ())
#define GMIME_SQ_CONTEXT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GMIME_TYPE_SQ_CONTEXT, GMimeSqContext))
#define GMIME_SQ_CONTEXT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GMIME_TYPE_SQ_CONTEXT, GMimeSqContextClass))
#define GMIME_SQ_IS_SQ_CONTEXT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GMIME_TYPE_SQ_CONTEXT))
#define GMIME_SQ_IS_SQ_CONTEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GMIME_TYPE_SQ_CONTEXT))
#define GMIME_SQ_CONTEXT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GMIME_TYPE_SQ_CONTEXT, GMimeSqContextClass))

typedef struct _GMimeSqContext GMimeSqContext;
typedef struct _GMimeSqContextClass GMimeSqContextClass;

struct _GMimeSqContext {
	GMimeCryptoContext parent;
};

struct _GMimeSqContextClass {
	GMimeCryptoContextClass parent_class;
};

// maybe this?
// typedef enum {
// 	GMIME_ACCESSMODE_ALWAYS,
// 	GMIME_ACCESSMODE_ONMISS,
// } GMimeAccessMode;

GType gmime_sq_context_get_type (void);

GMimeCryptoContext *gmime_sq_context_new (const char *path);

G_END_DECLS

#endif /* __GMIME_SQ_CONTEXT_H__ */
