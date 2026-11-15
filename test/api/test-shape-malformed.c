/*
 * Copyright © 2026  HarfBuzz contributors
 *
 *  This is part of HarfBuzz, a text shaping library.
 *
 * Permission is hereby granted, without written agreement and without
 * license or royalty fees, to use, copy, modify, and distribute this
 * software and its documentation for any purpose, provided that the
 * above copyright notice and the following two paragraphs appear in
 * all copies of this software.
 *
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN
 * IF THE COPYRIGHT HOLDER HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * THE COPYRIGHT HOLDER SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE COPYRIGHT HOLDER HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */

#include "hb-test.h"

#include <hb.h>
#include <hb-ot.h>

static void
put16 (GByteArray *a, unsigned v)
{
  guint8 b[2] = {(guint8) (v >> 8), (guint8) v};
  g_byte_array_append (a, b, 2);
}

static void
put32 (GByteArray *a, unsigned v)
{
  guint8 b[4] = {(guint8) (v >> 24), (guint8) (v >> 16),
		 (guint8) (v >> 8), (guint8) v};
  g_byte_array_append (a, b, 4);
}

static void
patch32 (GByteArray *a, unsigned offset, unsigned v)
{
  a->data[offset] = v >> 24;
  a->data[offset + 1] = v >> 16;
  a->data[offset + 2] = v >> 8;
  a->data[offset + 3] = v;
}

static void
put_tag (GByteArray *a, const char tag[4])
{
  g_byte_array_append (a, (const guint8 *) tag, 4);
}

static void
align4 (GByteArray *a)
{
  while (a->len & 3)
    g_byte_array_append (a, (const guint8 *) "\0", 1);
}

static GByteArray *
make_cmap12 (void)
{
  GByteArray *a = g_byte_array_new ();

  put16 (a, 0);		/* version */
  put16 (a, 1);		/* numTables */
  put16 (a, 3);		/* Windows */
  put16 (a, 10);	/* Unicode full repertoire */
  put32 (a, 12);	/* subtable offset */

  put16 (a, 12);	/* format */
  put16 (a, 0);		/* reserved */
  put32 (a, 16 + 12 * 4); /* length */
  put32 (a, 0);		/* language */
  put32 (a, 4);		/* numGroups */
  for (unsigned cp = 'a'; cp <= 'd'; cp++)
  {
    put32 (a, cp);
    put32 (a, cp);
    put32 (a, cp - 'a' + 1);
  }

  return a;
}

static GByteArray *
make_maxp (unsigned glyph_count)
{
  GByteArray *a = g_byte_array_new ();
  put32 (a, 0x00005000);
  put16 (a, glyph_count);
  return a;
}

static GByteArray *
make_gsub (const unsigned *coverage,
	   unsigned coverage_count,
	   unsigned set_count,
	   unsigned lig_glyph,
	   unsigned component)
{
  GByteArray *a = g_byte_array_new ();
  GByteArray *sub = g_byte_array_new ();
  unsigned coverage_offset = 6 + 2 * set_count + 10 * set_count;

  put32 (a, 0x00010000);
  put16 (a, 10);	/* ScriptList */
  put16 (a, 30);	/* FeatureList */
  put16 (a, 44);	/* LookupList */

  /* DFLT script with a default LangSys selecting feature 0. */
  put16 (a, 1);
  put_tag (a, "DFLT");
  put16 (a, 8);
  put16 (a, 4);
  put16 (a, 0);
  put16 (a, 0);
  put16 (a, 0xFFFF);
  put16 (a, 1);
  put16 (a, 0);

  /* 'liga' feature selecting lookup 0. */
  put16 (a, 1);
  put_tag (a, "liga");
  put16 (a, 8);
  put16 (a, 0);
  put16 (a, 1);
  put16 (a, 0);

  /* LookupList with one LigatureSubst lookup. */
  put16 (a, 1);
  put16 (a, 4);
  put16 (a, 4);		/* lookup type */
  put16 (a, 0);		/* lookup flag */
  put16 (a, 1);		/* subtable count */
  put16 (a, 8);		/* subtable offset */

  put16 (sub, 1);	/* format */
  put16 (sub, coverage_offset);
  put16 (sub, set_count);
  for (unsigned i = 0; i < set_count; i++)
    put16 (sub, 6 + 2 * set_count + 10 * i);

  for (unsigned i = 0; i < set_count; i++)
  {
    put16 (sub, 1);	/* one ligature in this set */
    put16 (sub, 4);	/* offset to it */
    put16 (sub, lig_glyph);
    put16 (sub, 2);	/* component count */
    put16 (sub, component);
  }

  put16 (sub, 1);	/* Coverage format 1 */
  put16 (sub, coverage_count);
  for (unsigned i = 0; i < coverage_count; i++)
    put16 (sub, coverage[i]);

  g_byte_array_append (a, sub->data, sub->len);
  g_byte_array_free (sub, TRUE);
  return a;
}

static GByteArray *
make_sfnt (GByteArray *maxp,
	   GByteArray *cmap,
	   GByteArray *gsub)
{
  struct table_t
  {
    const char *tag;
    GByteArray *data;
    unsigned record;
  } tables[] = {
    {"cmap", cmap, 0},
    {"GSUB", gsub, 0},
    {"maxp", maxp, 0},
  };
  const unsigned count = G_N_ELEMENTS (tables);
  GByteArray *a = g_byte_array_new ();

  put32 (a, 0x00010000);
  put16 (a, count);
  put16 (a, 0);
  put16 (a, 0);
  put16 (a, 0);

  for (unsigned i = 0; i < count; i++)
  {
    tables[i].record = a->len;
    put_tag (a, tables[i].tag);
    put32 (a, 0);
    put32 (a, 0);
    put32 (a, 0);
  }

  for (unsigned i = 0; i < count; i++)
  {
    align4 (a);
    unsigned offset = a->len;
    g_byte_array_append (a, tables[i].data->data, tables[i].data->len);
    patch32 (a, tables[i].record + 8, offset);
    patch32 (a, tables[i].record + 12, tables[i].data->len);
  }

  return a;
}

static hb_face_t *
face_from_bytes (GByteArray *data)
{
  hb_blob_t *blob = hb_blob_create ((const char *) data->data, data->len,
				    HB_MEMORY_MODE_READONLY, NULL, NULL);
  hb_face_t *face = hb_face_create (blob, 0);
  hb_blob_destroy (blob);
  return face;
}

static void
shape (hb_face_t *face, const char *text, hb_codepoint_t *glyphs,
       unsigned *length)
{
  hb_font_t *font = hb_font_create (face);
  hb_buffer_t *buffer = hb_buffer_create ();
  const char *shapers[] = {"ot", NULL};

  hb_buffer_add_utf8 (buffer, text, -1, 0, -1);
  hb_buffer_guess_segment_properties (buffer);
  g_assert_true (hb_shape_full (font, buffer, NULL, 0, shapers));
  g_assert_true (hb_buffer_allocation_successful (buffer));

  hb_glyph_info_t *info = hb_buffer_get_glyph_infos (buffer, length);
  for (unsigned i = 0; i < *length; i++)
    glyphs[i] = info[i].codepoint;

  hb_buffer_destroy (buffer);
  hb_font_destroy (font);
}

static GByteArray *
make_font (unsigned coverage_count,
	   unsigned set_count,
	   unsigned glyph_count)
{
  const unsigned legal_coverage[] = {2};
  const unsigned illegal_coverage[] = {1, 2};
  const unsigned *coverage = coverage_count == 1 ? legal_coverage : illegal_coverage;
  GByteArray *maxp = make_maxp (glyph_count);
  GByteArray *cmap = make_cmap12 ();
  GByteArray *gsub = make_gsub (coverage, coverage_count, set_count, 3, 1);
  GByteArray *font = make_sfnt (maxp, cmap, gsub);

  g_byte_array_free (maxp, TRUE);
  g_byte_array_free (cmap, TRUE);
  g_byte_array_free (gsub, TRUE);
  return font;
}

static void
test_shape_truncated_sfnt_fails (void)
{
  GByteArray *font = make_font (1, 1, 8);
  hb_blob_t *blob;
  hb_face_t *face;

  g_byte_array_set_size (font, font->len - 4);
  blob = hb_blob_create ((const char *) font->data, font->len,
			 HB_MEMORY_MODE_READONLY, NULL, NULL);
  face = hb_face_create_or_fail (blob, 0);
  g_assert_null (face);
  hb_blob_destroy (blob);
  g_byte_array_free (font, TRUE);
}

static void
test_shape_table_length_mismatch_fails (void)
{
  GByteArray *font = make_font (1, 1, 8);
  hb_blob_t *blob;
  hb_face_t *face;

  /* The maxp record is the third 16-byte record.  Make its length run
   * past the end of the blob without moving any data. */
  patch32 (font, 12 + 16 * 2 + 12, font->len);
  blob = hb_blob_create ((const char *) font->data, font->len,
			 HB_MEMORY_MODE_READONLY, NULL, NULL);
  face = hb_face_create_or_fail (blob, 0);
  g_assert_null (face);
  hb_blob_destroy (blob);
  g_byte_array_free (font, TRUE);
}

static void
test_shape_illegal_ligature_is_ignored (void)
{
  /* Coverage says glyph 2 is covered, but there is only one LigatureSet.
   * Indexing the missing second set used to reach an unsanitized alias. */
  GByteArray *font = make_font (2, 1, 8);
  hb_face_t *face = face_from_bytes (font);
  hb_codepoint_t glyphs[4];
  unsigned length;
  hb_font_t *probe = hb_font_create (face);
  hb_codepoint_t glyph;

  g_assert_true (hb_font_get_nominal_glyph (probe, 'b', &glyph));
  g_assert_cmpuint (glyph, ==, 2);
  g_assert_true (hb_font_get_nominal_glyph (probe, 'a', &glyph));
  g_assert_cmpuint (glyph, ==, 1);
  hb_font_destroy (probe);

  shape (face, "ba", glyphs, &length);
  g_assert_cmpuint (length, ==, 2);
  g_assert_cmpuint (glyphs[0], ==, 2);
  g_assert_cmpuint (glyphs[1], ==, 1);

  hb_face_destroy (face);
  g_byte_array_free (font, TRUE);
}

static void
test_shape_legal_ligature_unchanged (void)
{
  GByteArray *font = make_font (1, 1, 8);
  hb_face_t *face = face_from_bytes (font);
  hb_codepoint_t glyphs[4];
  unsigned length;

  shape (face, "ba", glyphs, &length);
  g_assert_cmpuint (length, ==, 1);
  g_assert_cmpuint (glyphs[0], ==, 3);

  hb_face_destroy (face);
  g_byte_array_free (font, TRUE);
}

static void
test_shape_huge_glyph_count_is_bounded (void)
{
  hb_face_t *face = hb_face_builder_create ();
  hb_face_set_glyph_count (face, G_MAXUINT);
  g_assert_cmpuint (hb_face_get_glyph_count (face), ==, 0xFFFFFFu);
  hb_face_destroy (face);

  GByteArray *font = make_font (1, 1, 0xFFFF);
  face = face_from_bytes (font);
  hb_codepoint_t glyphs[4];
  unsigned length;

  shape (face, "ba", glyphs, &length);
  g_assert_cmpuint (length, ==, 1);
  g_assert_cmpuint (glyphs[0], ==, 3);

  hb_face_destroy (face);
  g_byte_array_free (font, TRUE);
}

int
main (int argc, char **argv)
{
  hb_test_init (&argc, &argv);

  hb_test_add (test_shape_truncated_sfnt_fails);
  hb_test_add (test_shape_table_length_mismatch_fails);
  hb_test_add (test_shape_illegal_ligature_is_ignored);
  hb_test_add (test_shape_legal_ligature_unchanged);
  hb_test_add (test_shape_huge_glyph_count_is_bounded);

  return hb_test_run ();
}
