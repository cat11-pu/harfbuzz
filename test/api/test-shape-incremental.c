#include "hb-test.h"


static hb_font_t *
open_font (const char *path)
{
  hb_face_t *face = hb_test_open_font_file (path);
  hb_font_t *font = hb_font_create (face);
  hb_face_destroy (face);
  hb_font_set_scale (font, 1000, 1000);
  return font;
}

static hb_buffer_t *
shape_full_with (hb_font_t                      *font,
		 const char                     *text,
		 unsigned int                    text_len,
		 const hb_segment_properties_t  *props,
		 const hb_feature_t             *features,
		 unsigned int                    num_features)
{
  hb_buffer_t *buffer = hb_buffer_create ();
  hb_buffer_add_utf8 (buffer, text, text_len, 0, -1);
  if (props)
    hb_buffer_set_segment_properties (buffer, props);
  hb_buffer_guess_segment_properties (buffer);
  hb_shape (font, buffer, features, num_features);
  return buffer;
}

static hb_buffer_t *
shape_full (hb_font_t *font, const char *text, unsigned int text_len)
{
  return shape_full_with (font, text, text_len, NULL, NULL, 0);
}

static void
assert_clusters (hb_buffer_t *buffer, unsigned int text_bytes)
{
  unsigned int len;
  hb_glyph_info_t *info = hb_buffer_get_glyph_infos (buffer, &len);
  bool forward = HB_DIRECTION_IS_FORWARD (hb_buffer_get_direction (buffer));

  for (unsigned int i = 0; i < len; i++)
  {
    g_assert_cmpuint (info[i].cluster, <, text_bytes);
    if (i && info[i - 1].cluster != info[i].cluster)
      g_assert_cmpuint (forward ? info[i - 1].cluster : info[i].cluster,
			<,
			forward ? info[i].cluster : info[i - 1].cluster);
  }
}

static void
assert_prefix_unchanged (hb_buffer_t        *before,
			 hb_buffer_t        *after,
			 unsigned int        first_changed_cluster,
			 unsigned int        first_changed_glyph)
{
  unsigned int before_len, after_len;
  hb_glyph_info_t *before_info = hb_buffer_get_glyph_infos (before, &before_len);
  hb_glyph_info_t *after_info = hb_buffer_get_glyph_infos (after, &after_len);
  hb_glyph_position_t *before_pos = hb_buffer_get_glyph_positions (before, NULL);
  hb_glyph_position_t *after_pos = hb_buffer_get_glyph_positions (after, NULL);

  unsigned int prefix_len = 0;
  while (prefix_len < before_len &&
	 before_info[prefix_len].cluster < first_changed_cluster)
    prefix_len++;

  bool forward = HB_DIRECTION_IS_FORWARD (hb_buffer_get_direction (after));
  unsigned int before_start = forward ? 0 : before_len - prefix_len;
  unsigned int after_start = forward ? 0 : after_len - prefix_len;

  if (forward)
    g_assert_cmpuint (first_changed_glyph, ==, prefix_len);
  else
    g_assert_cmpuint (first_changed_glyph, ==, 0);

  g_assert_cmpuint (after_len, >=, prefix_len);
  for (unsigned int i = 0; i < prefix_len; i++)
  {
    hb_glyph_info_t *a = &before_info[before_start + i];
    hb_glyph_info_t *b = &after_info[after_start + i];
    hb_glyph_position_t *ap = &before_pos[before_start + i];
    hb_glyph_position_t *bp = &after_pos[after_start + i];

    g_assert_cmpuint (a->codepoint, ==, b->codepoint);
    g_assert_cmpuint (a->cluster, ==, b->cluster);
    g_assert_cmpuint (a->mask & HB_GLYPH_FLAG_DEFINED,
		      ==,
		      b->mask & HB_GLYPH_FLAG_DEFINED);
    g_assert_cmpint (ap->x_advance, ==, bp->x_advance);
    g_assert_cmpint (ap->y_advance, ==, bp->y_advance);
    g_assert_cmpint (ap->x_offset, ==, bp->x_offset);
    g_assert_cmpint (ap->y_offset, ==, bp->y_offset);
  }
}

static void
assert_matches_full (hb_font_t *font, hb_shape_incremental_t *incremental,
		     const char *text, unsigned int text_len)
{
  hb_buffer_t *actual = hb_shape_incremental_get_buffer (incremental);
  hb_buffer_t *reference = shape_full (font, text, text_len);

  g_assert_cmpuint (hb_buffer_diff (actual, reference, (hb_codepoint_t) -1, 0),
		    ==,
		    HB_BUFFER_DIFF_FLAG_EQUAL);

  hb_buffer_destroy (reference);
}

static void
assert_matches_full_with (hb_font_t                      *font,
			  hb_shape_incremental_t         *incremental,
			  const char                     *text,
			  unsigned int                    text_len,
			  const hb_segment_properties_t  *props,
			  const hb_feature_t             *features,
			  unsigned int                    num_features)
{
  hb_buffer_t *actual = hb_shape_incremental_get_buffer (incremental);
  hb_buffer_t *reference =
    shape_full_with (font, text, text_len, props, features, num_features);

  g_assert_cmpuint (hb_buffer_diff (actual, reference, (hb_codepoint_t) -1, 0),
		    ==,
		    HB_BUFFER_DIFF_FLAG_EQUAL);

  hb_buffer_destroy (reference);
}

static void
append_one (hb_font_t              *font,
	    hb_shape_incremental_t *incremental,
	    GString                *text,
	    const char             *chunk,
	    unsigned int            chunk_len,
	    unsigned int           *first_changed_cluster)
{
  hb_buffer_t *actual = hb_shape_incremental_get_buffer (incremental);
  hb_buffer_t *before = hb_buffer_create ();
  hb_buffer_append (before, actual, 0, -1);

  unsigned int old_text_bytes = text->len;
  unsigned int changed_cluster = UINT_MAX;
  unsigned int changed_glyph = UINT_MAX;
  g_assert_true (hb_shape_incremental_append_utf8 (incremental,
						   chunk, chunk_len,
						   &changed_cluster,
						   &changed_glyph));
  g_string_append_len (text, chunk, chunk_len);

  g_assert_cmpuint (changed_cluster, <=, old_text_bytes);
  g_assert_cmpuint (changed_glyph, <=, hb_buffer_get_length (actual));
  assert_prefix_unchanged (before, actual, changed_cluster, changed_glyph);
  assert_clusters (actual, text->len);

  if (first_changed_cluster)
    *first_changed_cluster = changed_cluster;

  hb_buffer_destroy (before);
}

static void
test_shape_incremental_latin (void)
{
  static const char *chunks[] = {"o", "f", "f", "i", "c", "e", " ", "A", "V", "A", "T", "A", "R"};
  hb_font_t *font = open_font ("fonts/NotoSans-Bold.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, NULL, 0);
  GString *text = g_string_new ("");

  g_assert_nonnull (incremental);
  for (unsigned int i = 0; i < G_N_ELEMENTS (chunks); i++)
  {
    append_one (font, incremental, text, chunks[i], strlen (chunks[i]), NULL);
    assert_matches_full (font, incremental, text->str, text->len);
  }

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

static void
test_shape_incremental_ligature (void)
{
  hb_font_t *font = open_font ("fonts/Roboto-Regular.gsub.fi.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, NULL, 0);
  GString *text = g_string_new ("");
  unsigned int changed_cluster;

  g_assert_nonnull (incremental);

  append_one (font, incremental, text, "f", 1, &changed_cluster);
  g_assert_cmpuint (changed_cluster, ==, 0);
  assert_matches_full (font, incremental, text->str, text->len);

  append_one (font, incremental, text, "i", 1, &changed_cluster);
  g_assert_cmpuint (changed_cluster, ==, 0);
  g_assert_cmpuint (hb_buffer_get_length (hb_shape_incremental_get_buffer (incremental)),
		    ==,
		    1);
  assert_matches_full (font, incremental, text->str, text->len);

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

static void
test_shape_incremental_arabic (void)
{
  static const char *chunks[] = {
    "\xD8\xB3", "\xD9\x84", "\xD8\xA7", "\xD9\x85", " ",
    "\xD9\x84", "\xD8\xA7", "\xD9\x85", "\xE2\x80\x8D", "\xD8\xA8"
  };
  hb_font_t *font = open_font ("fonts/NotoNastaliqUrdu-Regular.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, NULL, 0);
  GString *text = g_string_new ("");

  g_assert_nonnull (incremental);
  for (unsigned int i = 0; i < G_N_ELEMENTS (chunks); i++)
  {
    append_one (font, incremental, text, chunks[i], strlen (chunks[i]), NULL);
    assert_matches_full (font, incremental, text->str, text->len);
  }

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

static void
test_shape_incremental_props_inference (void)
{
  static const char *chunks[] = {
    " ", "\xD8\xB3", "\xD9\x84", "\xD8\xA7", "\xD9\x85"
  };
  hb_font_t *font = open_font ("fonts/NotoNastaliqUrdu-Regular.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, NULL, 0);
  GString *text = g_string_new ("");

  g_assert_nonnull (incremental);
  for (unsigned int i = 0; i < G_N_ELEMENTS (chunks); i++)
  {
    append_one (font, incremental, text, chunks[i], strlen (chunks[i]), NULL);
    assert_matches_full (font, incremental, text->str, text->len);
  }

  g_assert_cmpint (hb_buffer_get_direction (hb_shape_incremental_get_buffer (incremental)),
		   ==,
		   HB_DIRECTION_RTL);

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

static void
test_shape_incremental_vertical (void)
{
  static const char *chunks[] = {"A", "V", "A", "T", "A", "R"};
  hb_segment_properties_t props = HB_SEGMENT_PROPERTIES_DEFAULT;
  hb_font_t *font = open_font ("fonts/NotoSans-Bold.ttf");
  hb_shape_incremental_t *incremental;
  GString *text = g_string_new ("");

  props.direction = HB_DIRECTION_TTB;
  incremental = hb_shape_incremental_create (font, &props, NULL, 0);
  g_assert_nonnull (incremental);

  for (unsigned int i = 0; i < G_N_ELEMENTS (chunks); i++)
  {
    append_one (font, incremental, text, chunks[i], strlen (chunks[i]), NULL);
    g_assert_cmpint (hb_buffer_get_direction (hb_shape_incremental_get_buffer (incremental)),
		     ==,
		     HB_DIRECTION_TTB);
    assert_matches_full_with (font, incremental, text->str, text->len,
			      &props, NULL, 0);
  }

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

static void
test_shape_incremental_features (void)
{
  hb_feature_t features[] = {
    {HB_TAG ('l','i','g','a'), 0, 0, UINT_MAX}
  };
  hb_font_t *font = open_font ("fonts/Roboto-Regular.gsub.fi.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, features, G_N_ELEMENTS (features));
  GString *text = g_string_new ("");

  g_assert_nonnull (incremental);
  append_one (font, incremental, text, "f", 1, NULL);
  append_one (font, incremental, text, "i", 1, NULL);
  g_assert_cmpuint (hb_buffer_get_length (hb_shape_incremental_get_buffer (incremental)),
		    ==,
		    2);
  assert_matches_full_with (font, incremental, text->str, text->len,
			    NULL, features, G_N_ELEMENTS (features));

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

static void
test_shape_incremental_combining (void)
{
  static const char *chunks[] = {"e", "\xCC\x81", "x", "e", "\xCC\x88", "\xCC\x81"};
  hb_font_t *font = open_font ("fonts/NotoSans-Bold.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, NULL, 0);
  GString *text = g_string_new ("");
  unsigned int changed_cluster;

  g_assert_nonnull (incremental);
  for (unsigned int i = 0; i < G_N_ELEMENTS (chunks); i++)
  {
    append_one (font, incremental, text, chunks[i], strlen (chunks[i]),
		&changed_cluster);
    if (i == 1)
    {
      g_assert_cmpuint (changed_cluster, ==, 0);
      g_assert_cmpuint (hb_buffer_get_length (hb_shape_incremental_get_buffer (incremental)),
			>=,
			1);
    }
    assert_matches_full (font, incremental, text->str, text->len);
  }

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

static void
test_shape_incremental_errors (void)
{
  hb_font_t *font = open_font ("fonts/NotoSans-Bold.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, NULL, 0);
  GString *text = g_string_new ("");
  unsigned int changed_cluster, changed_glyph;

  g_assert_nonnull (incremental);
  append_one (font, incremental, text, "a", 1, NULL);

  changed_cluster = changed_glyph = 0;
  g_assert_true (hb_shape_incremental_append_utf8 (incremental, "", 0,
						   &changed_cluster,
						   &changed_glyph));
  g_assert_cmpuint (changed_cluster, ==, text->len);
  g_assert_cmpuint (changed_glyph, ==,
		    hb_buffer_get_length (hb_shape_incremental_get_buffer (incremental)));

  hb_buffer_t *before = hb_buffer_create ();
  hb_buffer_append (before, hb_shape_incremental_get_buffer (incremental), 0, -1);
  g_assert_false (hb_shape_incremental_append_utf8 (incremental, "\xC3", 1,
						    NULL, NULL));
  g_assert_cmpuint (hb_buffer_diff (hb_shape_incremental_get_buffer (incremental),
				    before, (hb_codepoint_t) -1, 0),
		    ==,
		    HB_BUFFER_DIFF_FLAG_EQUAL);
  hb_buffer_destroy (before);
  assert_matches_full (font, incremental, text->str, text->len);

  append_one (font, incremental, text, "\xC3\xA9", 2, NULL);
  assert_matches_full (font, incremental, text->str, text->len);

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);

  g_assert_null (hb_shape_incremental_get_buffer (NULL));
  g_assert_false (hb_shape_incremental_append_utf8 (NULL, "a", 1, NULL, NULL));

  hb_font_destroy (font);
}

static void
test_shape_incremental_10k (void)
{
  hb_font_t *font = open_font ("fonts/NotoSans-Bold.ttf");
  hb_shape_incremental_t *incremental =
    hb_shape_incremental_create (font, NULL, NULL, 0);
  GString *text = g_string_new ("");

  g_assert_nonnull (incremental);
  for (unsigned int i = 0; i < 10000; i++)
  {
    const char *chunk = (i % 17) ? "a" : " ";
    g_assert_true (hb_shape_incremental_append_utf8 (incremental,
						     chunk, 1, NULL, NULL));
    g_string_append_c (text, chunk[0]);
    assert_clusters (hb_shape_incremental_get_buffer (incremental), text->len);
    assert_matches_full (font, incremental, text->str, text->len);
  }

  g_string_free (text, TRUE);
  hb_shape_incremental_destroy (incremental);
  hb_font_destroy (font);
}

int
main (int argc, char **argv)
{
  hb_test_init (&argc, &argv);

  hb_test_add (test_shape_incremental_latin);
  hb_test_add (test_shape_incremental_ligature);
  hb_test_add (test_shape_incremental_arabic);
  hb_test_add (test_shape_incremental_props_inference);
  hb_test_add (test_shape_incremental_vertical);
  hb_test_add (test_shape_incremental_features);
  hb_test_add (test_shape_incremental_combining);
  hb_test_add (test_shape_incremental_errors);
  hb_test_add (test_shape_incremental_10k);

  return hb_test_run ();
}
