## Security Fuzzers

To build the fuzzers with libFuzzer to perform actual fuzzing, build with:

```shell
CXX=clang++ CXXFLAGS="-fsanitize=address,fuzzer-no-link" meson fuzzbuild --default-library=static -Dfuzzer_ldflags="-fsanitize=address,fuzzer"

ninja -Cfuzzbuild
```

Then, run the fuzzer like this:

fuzzbuild/test/fuzzing/hb-{shape,raster,vector,subset,repacker,depend}-fuzzer [-max_len=2048] [CORPUS_DIR]

Where max_len specifies the maximal length of font files to handle.
The smaller the faster.

Note: The `depend` fuzzer requires `-Ddepend_api=true` meson option.

For more details consult the following locations:
  - http://llvm.org/docs/LibFuzzer.html

## Randomized Shape Property Test

`random-shape-property.py` generates random SFNT fonts and mixed-direction
texts, then shapes every case twice in fresh processes.  It checks for
sanitizer errors, leaks, timeouts, nonzero exits, and glyph-sequence
non-determinism.  Failures are reduced at table and Unicode code point
granularity and written with a reproduction command.

Build an instrumented `hb-shape` and run 200 cases:

```shell
meson setup build-asan --buildtype=debug -Db_sanitize=address,undefined \
  -Dglib=enabled -Dfreetype=disabled -Dcairo=disabled -Dicu=disabled \
  -Dgraphite2=disabled -Dgobject=disabled -Ddocs=disabled -Dtests=disabled \
  -Draster=disabled -Dvector=disabled -Dgpu=disabled -Dsubset=disabled \
  -Dintrospection=disabled -Dutilities=enabled
meson compile -C build-asan hb-shape
python3 test/fuzzing/random-shape-property.py \
  --hb-shape build-asan/util/hb-shape --cases 200
```

The report, per-case metadata, and minimized counterexamples are written under
`artifacts/shape-property-200/`.  Use `--keep-fonts` to retain all generated
font files, or `--verify` to additionally exercise `hb_buffer_verify`.

## Depend Closure Parity Test

The `hb-depend-closure-parity` test is distinct from the security fuzzers.
While security fuzzers test robustness against malformed input, the closure
parity test validates correctness by emulating the glyph closure calculation
used for subsetting with one generated from the dependency graph to avoid
implementation divergence. It should only be run on valid fonts.
