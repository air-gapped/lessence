# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v0.1.0.html).

## [0.8.0](https://github.com/air-gapped/lessence/compare/v0.5.0...v0.8.0) (2026-09-22)

0.6.0 and 0.7.0 were tagged but never published. Their changes are listed
here, so this section is everything since 0.5.0.


### ⚠ BREAKING CHANGES

* a default run writes a report to disk and prints a bounded overview of it on stdout instead of the folded text; `--no-report` restores the 0.5.0 output, and is what `tail -f` and any source without an end need
* the briefing's count of bare numbers is `numbers`, not `percentages`, in `--stats-json`, the JSON summary record and the briefing text


### Features

* a default run saves the complete folded report to a file and prints a bounded overview of it ([29b27de](https://github.com/air-gapped/lessence/commit/29b27de98e0e2bc3c8b2279cfc818a7afb7dfbcd))
* --skill prints the bundled agent skill, version-locked to the binary; --skill flags prints the flag reference ([dc87751](https://github.com/air-gapped/lessence/commit/dc87751f143cac696aa1d644fff6f23b0adf3adf))
* JSON summary and --preflight records carry schema_version, the build version, a SHA-256 identity of the input and a list of what was degraded, with a repair for each ([9910979](https://github.com/air-gapped/lessence/commit/99109796e8aa177f4a9a94311951f4efe0ff32c6))


### Bug Fixes

* --help addresses coding agents first and points at the bundled skill; --help-human for people ([c488bea](https://github.com/air-gapped/lessence/commit/c488beab0d18f7302bf07b671758b129e09a28af))
* a bare `lessence` at a terminal prints the help instead of waiting on stdin ([975a2ac](https://github.com/air-gapped/lessence/commit/975a2aca07b5a89eda1fcafe0c5151dcf70d0fb5))
* the overview of a saved report streams, stays inside its budget, and never hides what it does not know ([8e855c4](https://github.com/air-gapped/lessence/commit/8e855c4fc99ee7264c13577e8480a79df2e7d141))
* an aborted run prints no template statistics; framed continuations no longer trip the record count ([5d8deb7](https://github.com/air-gapped/lessence/commit/5d8deb7bbf9c2107f4382fe61d71c7de1038d9e7))
* the briefing counts numbers as numbers, not as percentages ([15e00e3](https://github.com/air-gapped/lessence/commit/15e00e345d8c7e24fd70763fa6b67274c02829de))


### Performance Improvements

* a default run no longer reads its own report back to print the overview ([f3b9d5a](https://github.com/air-gapped/lessence/commit/f3b9d5a0a6a73c5d9bc3db29151cf4ffc5d66a65))

## [0.5.0](https://github.com/air-gapped/lessence/compare/v0.4.5...v0.5.0) (2026-09-18)


### Features

* --diff shows which lines fold differently between two lessence builds ([131e79a](https://github.com/air-gapped/lessence/commit/131e79a5dedd208f2ac7aa53320b4e4bd17a23ba))
* --explain says which group a line came closest to joining, and why not ([792cd21](https://github.com/air-gapped/lessence/commit/792cd216370c2c390a9720cc23d0a9613d70767f))
* --frame-continuations folds a stack trace as one event ([92c1804](https://github.com/air-gapped/lessence/commit/92c1804421808b91c62b0f6f3e4d768d0b90b090))
* --sanitize &lt;entity&gt;[:&lt;action&gt;] masks hosts and addresses, and can pseudonymise instead of redact ([51eaaae](https://github.com/air-gapped/lessence/commit/51eaaae1721c7c978785496f8292ae83a23c62aa))
* --sanitize-pii masks credential-class values (key assignments, JWTs, provider keys) ([997f0bf](https://github.com/air-gapped/lessence/commit/997f0bfe7df8b4241d0beb1db49329c02c486544))
* --version reports the commit and target the binary was built from ([a6fc881](https://github.com/air-gapped/lessence/commit/a6fc881d253fc3023667971dc129167f08042de9))
* an orientation briefing replaces the compression report ([0828efa](https://github.com/air-gapped/lessence/commit/0828efaf25b0c7ca9c3d9fbaa07a979b708bcfc5))
* keep different endpoints and devices in separate groups ([4800408](https://github.com/air-gapped/lessence/commit/4800408a741e01c30dfd8d920cfa6a46f61cbc14))
* make the bundled skill discoverable by more agents ([986943a](https://github.com/air-gapped/lessence/commit/986943af797762c4c24cddbba08329d60b0bb37a))
* preserve exact source locations in JSON output ([02d3e33](https://github.com/air-gapped/lessence/commit/02d3e337cfa2a44771e964e6a92118fc1d3d9467))
* report completeness of JSON output ([fcf0ec6](https://github.com/air-gapped/lessence/commit/fcf0ec6a738380f335bab3a77b525b01e2539bca))
* the rollup reports words that vary inside a group even when no detector tokenised them ([334bea8](https://github.com/air-gapped/lessence/commit/334bea80c63cc4feb15c1eb7525d9a9854f2c32a))


### Bug Fixes

* --explain reports one record per event, not one per eviction ([75134da](https://github.com/air-gapped/lessence/commit/75134da52226805d3dffd79565ff2f2a5cf442be))
* --format markdown now errors with --top, --summary, --fit, --preflight ([c731e53](https://github.com/air-gapped/lessence/commit/c731e53870dedf6803a5e9b1f94c41e8ac688a62))
* --format md, MARKDOWN, and JSON aliases now emit their format instead of text ([0d9dd42](https://github.com/air-gapped/lessence/commit/0d9dd42fcd350ab462ad76f4b4a6503ca8aeae49))
* --preflight now strips terminal escapes like every other mode ([a67e5ed](https://github.com/air-gapped/lessence/commit/a67e5edc40c03a3213ee23b5a3c6b6afd2314993))
* --sanitize-pii credential masking now applies in --essence mode too ([70735b2](https://github.com/air-gapped/lessence/commit/70735b2c2094ef3e4648c2a30e412c993fe30455))
* --sanitize-pii now masks emails in every output mode ([8bd8b39](https://github.com/air-gapped/lessence/commit/8bd8b3964587325e4565aa7d2d523d4b034b6916))
* --summary and --top no longer silently drop patterns past 1000 groups with --threads 1 ([21e1359](https://github.com/air-gapped/lessence/commit/21e1359c88156764161ac8db09f847788ddedb61))
* --threads N now actually sizes the thread pool ([84629ca](https://github.com/air-gapped/lessence/commit/84629ca67ad2bed08e8edd84f453f5b158e3067d))
* --threads now caps at available parallelism instead of spawning N raw threads ([25a31ed](https://github.com/air-gapped/lessence/commit/25a31ed562271a9bf4663277d7262f371d896b8e))
* a 12-hour clock keeps its AM/PM, a compact `20260801142207` stamp and an IBM `26.213 14:22:07` stamp are timestamps on any line, `PT30M15S` is a duration, and a bare epoch is a timestamp only as the line's first token ([843b15e](https://github.com/air-gapped/lessence/commit/843b15e1b582eaa36e0f87e337ef273b812f6312))
* a bracketed number is a pid only in a tag, `-sdown` is a sign not a flag, `ssh-ed25519` is a word, `3f00b880.mailbox` is an address, `request: tokenreviews` is prose, a program path in the syslog tag stays whole, `daemon.info` is not a domain, a quoted sentence keeps its words, and `slot[1]` folds with `slot[2]` ([48d7dcb](https://github.com/air-gapped/lessence/commit/48d7dcb8dbdb8d0308880064f7c114945e028078))
* a dotted name is erased as a host only when the line says it is one ([b3c744c](https://github.com/air-gapped/lessence/commit/b3c744cbf29a4efb19f7350f5ac5be4d7069e768))
* a folded group's line says &lt;VARIES&gt; where its members disagree, and the rollup counts every variant — the one Server Reject among 7,164 Server Busy is visible again ([db41c59](https://github.com/air-gapped/lessence/commit/db41c595c196dece6262423d4fd78e50daf4f921))
* a JSON string value that is a sentence keeps its words — five gateway tasks were one "msg":&lt;KEY_VALUE&gt; group of 13,590 lines — and a quoted sentence with an escape in it is no longer erased as &lt;ESCAPED_JSON&gt; ([93d0841](https://github.com/air-gapped/lessence/commit/93d0841fdeea080c25e83dc56422a006d6969a62))
* a klog call site, a systemd unit and an auditd record type are event identity — lines from different ones no longer merge ([3779075](https://github.com/air-gapped/lessence/commit/3779075827602c1c803cc3c81f25f6a05d5ecf58))
* a kubectl log prefix names its workload and container, so two containers of one pod no longer print the same line ([d3fdf21](https://github.com/air-gapped/lessence/commit/d3fdf21c2b8a350071496ffc49326af97d72df96))
* a line with no foldable key or unit skips the key-value regexes and a pair is read off its match, so a kubelet log folds as fast as before the word vetoes went ([a46b6f0](https://github.com/air-gapped/lessence/commit/a46b6f0de0b5c65bbfdd8671da8bfb36b73c62b5))
* a MAC address is one atom (&lt;MAC&gt;) — its last byte is no longer read as a port or a size ([9f7a575](https://github.com/air-gapped/lessence/commit/9f7a575e79dcb81483f0861d1cfd0c7cba6d7893))
* a message made of key=number pairs is a metrics dump — every value folds and the key stays, so 899 Go memory-stats lines are one line again ([ff7451b](https://github.com/air-gapped/lessence/commit/ff7451bc63f6339486983ea6db4407a0be720743))
* a quoted sentence is the event, not a variable ([e63820c](https://github.com/air-gapped/lessence/commit/e63820c70e020e1b19f86b1de425794c2e28c29b))
* a repeated event is one line with one count, not several ([e1cc568](https://github.com/air-gapped/lessence/commit/e1cc568cda7ad2e36826c098ea3dd830192911f9))
* a route keeps the digit inside a word, so a Kubernetes path reads k8s and not k&lt;N&gt;s ([3745830](https://github.com/air-gapped/lessence/commit/37458303e2455058189c3136ff263a7df6d6becc))
* a spaced multi-unit duration and a µs value are one duration, `775.5M` and `256Mi` are one size, a `\x2d`-escaped UUID in a systemd unit name is a UUID, an id-named JSON field like `"execID"` folds as an id, a JSON event line is not a key-value line, a klog header is read in any month, and the program in `exe=`, `comm=` and `"binary":` is matched, never scored ([2c744ea](https://github.com/air-gapped/lessence/commit/2c744eaf459479654d23faaa74b24ccbd0cf4090))
* a syslog program name after facility.level stays visible ([549c524](https://github.com/air-gapped/lessence/commit/549c524232c1482493fd90093ed7529fb7fc31f1))
* a syslog/journal host between the timestamp and the program tag folds to &lt;HOST&gt;, so one event reported by several devices reads as one group ([5606ff1](https://github.com/air-gapped/lessence/commit/5606ff1adda761ee32d6730027561f72e44234cd))
* a word elsewhere on the line no longer changes how a field folds ([8a9e15a](https://github.com/air-gapped/lessence/commit/8a9e15af00338e71a37ef4f609b7e36c8460c18b))
* an access log folds by route, and the route is on the line — a group split by an anchor no longer prints a template identical to its neighbour's ([a5e409e](https://github.com/air-gapped/lessence/commit/a5e409e310c25228980de1ad0a9c135cd627725e))
* an audit record's sequence counter folds whatever its digit count, and an id field's value is an id whatever its charset ([5758ace](https://github.com/air-gapped/lessence/commit/5758ace98d53f6480ee220e139e33cb890aff9f2))
* asctime is one timestamp (weekday and year included), the kernel uptime stamp is one shape at any width, a bracket glued to a word is an index, a 16-digit epoch is a time not a hash, and two small integers no longer keep a short line from folding ([7dd3577](https://github.com/air-gapped/lessence/commit/7dd3577ffc6cbaae3a6c044b3f659405081eb744))
* distinguish CPU resource quantities from minutes ([048abfc](https://github.com/air-gapped/lessence/commit/048abfc185465151b90fb5fcfd31462db3bd337a))
* fold a field value on its shape, not on how long it happens to be ([2632344](https://github.com/air-gapped/lessence/commit/2632344ee82cf3fbfc38a99beb669096fa755860))
* fold a JSON field's number whatever its digit count ([92ea725](https://github.com/air-gapped/lessence/commit/92ea725d1fda18e6dda419367945797310460d44))
* JSON keys keep their name whatever folds them, and --explain names an anchor mismatch ([3921636](https://github.com/air-gapped/lessence/commit/39216369a8eb797ac6b1bac69a79e5c619083018))
* keep CLI option names visible and separate ([ff14716](https://github.com/air-gapped/lessence/commit/ff147167f570b36e6dd0276e5259bb5871db32c8))
* keep late variants in their original groups after eviction ([9d978dd](https://github.com/air-gapped/lessence/commit/9d978dde1b1409c3be29168ddbed5ed18a07217a))
* keep long decimal fractions out of timestamps ([60d90a5](https://github.com/air-gapped/lessence/commit/60d90a5184d74d5e2454a192b36dbe7db3670eaa))
* keep PCI device addresses visible when log paths vary ([9cc46ec](https://github.com/air-gapped/lessence/commit/9cc46ecc5ee74712bdd97f765ecc905dc6d68d2a))
* keep prose HTTP methods and routes distinct ([c872001](https://github.com/air-gapped/lessence/commit/c8720016961739f4caace7cfca616745a080cfed))
* keep request routes visible when HTTP methods vary ([df1405d](https://github.com/air-gapped/lessence/commit/df1405de41469cc8513a71f98f0945768a3f25e9))
* keep successful and failed audit syscalls separate ([f7b2db7](https://github.com/air-gapped/lessence/commit/f7b2db7da79d2adb50c931701fcd6f6118df51ef))
* keep top-N JSON output valid for agents ([1492951](https://github.com/air-gapped/lessence/commit/14929514158de49f47f6a679d9ffdab7bfed5a94))
* Kubernetes pod names fold whatever their kind — the 5-char suffix after a template hash or job number, the namespace in pod="ns/name", and the kube-api-access volume suffix no longer split groups ([d1998a3](https://github.com/air-gapped/lessence/commit/d1998a3b41fc6cfd0791cbd929fbdcec2b14f1f0))
* long structured records fold again instead of one group each ([65d046f](https://github.com/air-gapped/lessence/commit/65d046fac8d31f654b458da71d3dea0314a418d9))
* one lines_saved definition across every output mode ([96e2cf8](https://github.com/air-gapped/lessence/commit/96e2cf80e666b193ad062d145a1e1ba1d2c6892d))
* placeholders replace only what they matched — no invented pid= or request_id= labels — and versions, ssh fingerprints, compressed IPv6, exit statuses, dotted versions and 2025/09/14 dates are read for what they are ([4959f1d](https://github.com/air-gapped/lessence/commit/4959f1dfe60b3678a36eb4cb5c4bc1480640ced0))
* preserve known values when merging capped rollups ([83828c2](https://github.com/air-gapped/lessence/commit/83828c2b92c7136cf7d9dd517fffb4ff7d3aac38))
* pseudonym tags are HMAC-SHA256 under a per-run key from the operating system ([688513b](https://github.com/air-gapped/lessence/commit/688513b057a73ce56477c8b1c08e354ec73a8ebc))
* raise default similarity threshold to 83 — restores HTTP-status and state separation ([f1477b1](https://github.com/air-gapped/lessence/commit/f1477b123b9d93017001b20b4fedc2a9bc58769e))
* show call sites and programs that distinguish log events ([e820301](https://github.com/air-gapped/lessence/commit/e8203015dbe514a27a434e3950f6100f9fb772dd))
* show status classes that keep log events separate ([04ef7cd](https://github.com/air-gapped/lessence/commit/04ef7cd2e66d2cccefdd4c936183b9acfc378fb5))
* show systemd unit identities and retain instance names ([3e9e01a](https://github.com/air-gapped/lessence/commit/3e9e01a553d29f900c2ae6c248dd7cb8094f9238))
* six token shapes read right — a word:NN: line reference is not a port, 0x22 is not an address, 192-168-7-0-24 is one identifier, ED25519 is not a hash, a bracket chain keeps the space after it, and a URL gives back its closing bracket ([81a8008](https://github.com/air-gapped/lessence/commit/81a8008bd7e9db251615259ed45a2027ba40764e))
* structured JSON/logfmt messages keep their content instead of collapsing into one group ([21f51de](https://github.com/air-gapped/lessence/commit/21f51de6612bf5f24bfa18abcea4bbd041de086f))
* the same log always folds the same way ([9da393b](https://github.com/air-gapped/lessence/commit/9da393bedf1bb26915fc183cd05a6717299cf9a2))
* the shown line holds for every member — a placeholder against a plain word, a shorter member, a quoted value with spaces all become &lt;VARIES&gt; with counts; a line two sentence words apart founds its own group; kubectl container, structured caller, call site, traceback frame, JSON method/status/route and sha256 digests are matched, never scored ([6ffb87c](https://github.com/air-gapped/lessence/commit/6ffb87c77fab028b66ab6fe086b35927fb53005b))
* two groups that converge on the same template are shown as one line with one count ([729ee4e](https://github.com/air-gapped/lessence/commit/729ee4e553508f8670c78652b887273cd727b0b8))
* two more timestamp shapes — a dash-joined date-time (2025-06-26-00:45:05.454) and a datetime wrapped in its weekday and zone (Thu 2025-10-30 16:53:44 CET) are one timestamp ([b1cffa9](https://github.com/air-gapped/lessence/commit/b1cffa94c731cf8043e18002219cb6d58723ec1c))
* ULIDs and Kubernetes group/versions get their own placeholders; label keys, image refs, relative paths and dotted hostnames are one token instead of being cut at the slash ([629183d](https://github.com/air-gapped/lessence/commit/629183d95aaa865e4941b9ead96d863b02f81bfb))


### Performance

* avoid repeated timestamp scans on ASCII logs ([5a9e67f](https://github.com/air-gapped/lessence/commit/5a9e67ffa22c4d4e72e9be6408385043f58306b8))
* cache quoted-string normalization for repeated values ([3f70405](https://github.com/air-gapped/lessence/commit/3f704050f606e6cd157d358ae5a8432ab8d4cbc4))

## [0.4.5](https://github.com/air-gapped/lessence/compare/v0.4.4...v0.4.5) (2026-06-10)


### Performance

* up to 4x faster folding with byte-identical output ([c7efaea](https://github.com/air-gapped/lessence/commit/c7efaea633bced3fb2ebdad2b0677f3556b96ace))

## [0.4.4](https://github.com/air-gapped/lessence/compare/v0.4.3...v0.4.4) (2026-06-09)


### Bug Fixes

* --disable-patterns brackets/json/key-value now disables all matching detectors ([0b87792](https://github.com/air-gapped/lessence/commit/0b877925a3babcdb29b8b38b40529f0720d977ef))
* --stats-json and JSON summary report accurate per-category pattern counts ([23aea53](https://github.com/air-gapped/lessence/commit/23aea5369b02377f04ebaaa0a50c7e64cfae04ea))
* dotted code identifiers like hibernate.SQL are no longer detected as hostnames ([13e530a](https://github.com/air-gapped/lessence/commit/13e530ad5c2b6fba6a46c82eedc866d27c57a28c))
* epoch timestamps and hex-looking words are no longer detected as hashes ([a585a63](https://github.com/air-gapped/lessence/commit/a585a638363e7cf083b9efeb89860a22185dc449))
* exit with code 1 when an input file cannot be opened ([b10701f](https://github.com/air-gapped/lessence/commit/b10701fc94a4c19996786988504e1d75296e0aa3))
* log lines containing the word "request" are no longer rewritten as request IDs ([1446f48](https://github.com/air-gapped/lessence/commit/1446f48562e029d2491c18e26f5979d798449a58))
* parenthesized counts like "(3)" are no longer rewritten as PIDs ([a67adf6](https://github.com/air-gapped/lessence/commit/a67adf6536cea5d70ae49e96d461fb880e7b0846))
* similarity grouping now tolerates inserted tokens instead of splitting groups ([349493a](https://github.com/air-gapped/lessence/commit/349493a9fafdfde3121c77e84fb5549be1fc7a58))
* statistics footer now goes to stderr, keeping stdout clean for pipelines ([7893fcd](https://github.com/air-gapped/lessence/commit/7893fcdba96126bc8d8aac2caa5b5962f783479c))


### Performance

* flush remaining groups in O(n) instead of O(n^2) ([2fcb135](https://github.com/air-gapped/lessence/commit/2fcb1350b4c16d83cdbd05c9f68f0271ecd627fd))
* long key=value lines no longer stall the key-value detector ([1485e11](https://github.com/air-gapped/lessence/commit/1485e11f0d8103aa92ef98262a521b4a5d29d18a))

## [0.4.3](https://github.com/air-gapped/lessence/compare/v0.4.2...v0.4.3) (2026-05-31)


### Bug Fixes

* prevent crashes and injection from crafted log lines ([da1800b](https://github.com/air-gapped/lessence/commit/da1800bf5abb09074fb15cb33a41e909226ab470))

## [0.4.2](https://github.com/air-gapped/lessence/compare/v0.4.1...v0.4.2) (2026-05-03)


### Performance

* cache kubernetes detector regexes in LazyLock ([9779568](https://github.com/air-gapped/lessence/commit/97795680b5332fbeed56324de7b1086f21a6ca5e))
* use mimalloc as global allocator on musl ([88e4f04](https://github.com/air-gapped/lessence/commit/88e4f04e097d8f87218b1d80577290937e1d90d2))

## [0.4.1](https://github.com/air-gapped/lessence/compare/v0.4.0...v0.4.1) (2026-04-15)


### Bug Fixes

* eliminate flaky scaling tests with median-of-3 and nextest retries ([0a99de3](https://github.com/air-gapped/lessence/commit/0a99de3b009d8ca9cd538063264a653704bd92d7))
* **folder:** guard apply_pii_masking against empty emails and non-advancing loops ([117e031](https://github.com/air-gapped/lessence/commit/117e0316fd443919a4a5f5a843d844c6a0c54dd3))
* honor --disable-patterns for json, kubernetes, and 5 other silent no-ops ([fe1ccf2](https://github.com/air-gapped/lessence/commit/fe1ccf2df8a1512ff99969f95a20acae5f11c936))
* remove --disable-patterns decimal (never implemented; use duration) ([8ef9666](https://github.com/air-gapped/lessence/commit/8ef9666003289b0d7a4de892d0ed5b757eefd9b9))


### Performance

* optimize mutation testing from ~2.3s to ~0.7s per mutant ([79cf133](https://github.com/air-gapped/lessence/commit/79cf1333431ff23d92c2d44637f4532e947123db))
* optimize test suite from 17.6s to 2.5s in debug mode (7x faster) ([264b724](https://github.com/air-gapped/lessence/commit/264b724dd1d85b5564cbf024f99082b72b8f9acd))

## [0.4.0](https://github.com/air-gapped/lessence/compare/v0.3.1...v0.4.0) (2026-04-12)


### Features

* **folder:** compute per-group rollup metadata at flush time ([b6b235d](https://github.com/air-gapped/lessence/commit/b6b235db12a68cd72caf797eb3ae3443144aef43))
* **folder:** enrich text-mode compact marker with time range and rollups ([0d019ff](https://github.com/air-gapped/lessence/commit/0d019ff77e019d0c2eee9b5ce6f73326b8f13317))
* **folder:** retire rollup placeholders with corpus-calibrated values ([a896ae5](https://github.com/air-gapped/lessence/commit/a896ae52b6cb1818d33cb91244a316ff00e3f8cd))
* **format:** add --format json emitting JSONL with group and summary records ([cac1a8b](https://github.com/air-gapped/lessence/commit/cac1a8bea4790861e7ecf46e7eed3dc86a8f82eb))


### Bug Fixes

* pass crates.io OIDC token to cargo publish via env var ([0bfda2a](https://github.com/air-gapped/lessence/commit/0bfda2a0377cf52eaa6ad7f09e795e6f6e67054e))
* pass crates.io token explicitly to cargo publish ([2552e67](https://github.com/air-gapped/lessence/commit/2552e6727af62ac7921d3657877708bd7778d6e4))


### Reverts

* restore original cargo publish pattern without --token ([08fffe7](https://github.com/air-gapped/lessence/commit/08fffe7ed5265a71cf64cc57165049d83dfedfc2))

## [0.3.1](https://github.com/air-gapped/lessence/compare/v0.3.0...v0.3.1) (2026-04-05)


### Features

* add --fit (--human) flag for screen-sized log overview ([fb06155](https://github.com/air-gapped/lessence/commit/fb06155b16ee2db4b1d7cb33c4ae5ada02f38398))


### Bug Fixes

* allow name origin mention of logfold in README ([a4ad912](https://github.com/air-gapped/lessence/commit/a4ad912602c4efc747e9d234021c83bb5b26c4c0))
* fix flaky security overhead benchmark ([1d36b87](https://github.com/air-gapped/lessence/commit/1d36b870bedc849e9c9201df80bb167a502bc059))

## [0.3.0](https://github.com/air-gapped/lessence/compare/v0.2.0...v0.3.0) (2026-04-03)


### Features

* auto-truncate long lines in --summary to terminal width ([0165591](https://github.com/air-gapped/lessence/commit/0165591c0b42101b413c4ecf3e3a00a42fae222c))
* default cap of 30 patterns in --summary mode ([6153a82](https://github.com/air-gapped/lessence/commit/6153a82d3bb88b6adbd1f0088e922fe495260641))


### Bug Fixes

* remove hardcoded 200-char truncation from --summary output ([0722aeb](https://github.com/air-gapped/lessence/commit/0722aebb4210c23f5c956c0297980db8d116caf4))
* replace unmaintained atty crate with std::io::IsTerminal ([3970da8](https://github.com/air-gapped/lessence/commit/3970da8bc8dcd65bcea8c5500286fa70b1cd44c5))
* stabilize timing-dependent tests under parallel execution ([694f2d2](https://github.com/air-gapped/lessence/commit/694f2d2f880b8508a2da859ba0f449f373d5c413))


### Performance Improvements

* change default --threshold from 85 to 75 ([b80432c](https://github.com/air-gapped/lessence/commit/b80432c2c2f1f992a796f6ddfcab3ae6636e7b2c))

## [0.1.2](https://github.com/air-gapped/lessence/compare/v0.1.1...v0.1.2) (2026-04-01)


### Bug Fixes

* add id-token permission for claude oauth in release notes ([c0d8601](https://github.com/air-gapped/lessence/commit/c0d86018a1929916a9c4ac2928ba82f28298d2e6))
* add workflow_dispatch trigger and id-token to release notes ([d2addbc](https://github.com/air-gapped/lessence/commit/d2addbca60840009751d7e77449f558e529cda2d))
* move release notes to separate workflow_run trigger ([988ee50](https://github.com/air-gapped/lessence/commit/988ee50652f15316126f5f78106323ae7af46a9c))
* replace claude-code-action with bash script for release notes ([f807033](https://github.com/air-gapped/lessence/commit/f807033d2d2ddf0dba0e6a88acc2d8dcb3b599ae))


### Performance Improvements

* add content-aware pre-filters to skip wasteful detector calls ([670d963](https://github.com/air-gapped/lessence/commit/670d96383c326f19c0168a40647944a62b966d15))
* optimize grouping pipeline — 45% faster parallel, 54% faster worst-case ([3905872](https://github.com/air-gapped/lessence/commit/3905872f1bdcd6e8ae1d507c5223818477f1539e))

## [0.1.1](https://github.com/air-gapped/lessence/compare/v0.1.0...v0.1.1) (2026-04-01)


### Bug Fixes

* checkout and upload at tag ref, not branch ref ([52618a8](https://github.com/air-gapped/lessence/commit/52618a8d314af707f223ed3aacbf5e725af88a08))

## 0.1.0 (2026-04-01)


### Features

* accept file arguments (lessence app.log) ([5818e21](https://github.com/air-gapped/lessence/commit/5818e214ca36cd2554b98b59324ab8a0deb5c95a))
* add --completions flag for shell completion generation ([74d2067](https://github.com/air-gapped/lessence/commit/74d20675ef9479734ab63d11857ef5e844416ba3))
* add --fail-on-pattern for CI exit code gating ([4492d36](https://github.com/air-gapped/lessence/commit/4492d362d619f28917c05d590abc86d54cf163c3))
* add --stats-json flag for machine-readable statistics on stderr ([8c1d240](https://github.com/air-gapped/lessence/commit/8c1d240d531da47505b335b0fe74636848967673))
* add --top N flag for frequency-sorted output ([23dd032](https://github.com/air-gapped/lessence/commit/23dd032d744b32465032e721d41a117fa11458d0))
* add -q/--quiet alias for --no-stats ([43817d6](https://github.com/air-gapped/lessence/commit/43817d69b207e4a7fa31c9c351010cdb1ea39d82))
* add release workflow with prebuilt binaries for 5 platforms ([a9364d2](https://github.com/air-gapped/lessence/commit/a9364d2bde3f134d715655178e73a183aee4c807))
* switch to release-please with AI-generated release notes ([9400371](https://github.com/air-gapped/lessence/commit/940037104d065211fc2813d8d94f609f144f4129))


### Bug Fixes

* add cargo doc, cargo deny, and taiki-e/install-action to CI ([65e05e7](https://github.com/air-gapped/lessence/commit/65e05e7eb6692794289fb687c41e2b2c31fef0d9))
* add release bot to allowed_bots, fix release notes prompt ([70e5b7e](https://github.com/air-gapped/lessence/commit/70e5b7e8e047344ce65f6bfd4e937d41acd26abf))
* dereference annotated tag SHAs to commit SHAs in release workflow ([a9774eb](https://github.com/air-gapped/lessence/commit/a9774eb23d92e02e91afc651d4d3e4efb627af32))
* enforce cargo fmt, fix rustfmt.toml, add format check to CI ([f3db34c](https://github.com/air-gapped/lessence/commit/f3db34c902b5479ac66c14f7b6f3c1dc8a4692e0))
* remove cast_lossless allow, use From for safe casts ([0c9d74b](https://github.com/air-gapped/lessence/commit/0c9d74b3d4ab3789e178c84db5b2512e8358e918))
* remove LLM references from help text ([262f6fc](https://github.com/air-gapped/lessence/commit/262f6fc400be5251f42479bd0d91b24cc4c2371d))
* remove manual_string_new allow (already fixed) ([0ba22b3](https://github.com/air-gapped/lessence/commit/0ba22b3f1d8db3f2d388485161124bf828a59586))
* remove needless_raw_string_hashes allow, strip 4 extra hashes ([e9cf051](https://github.com/air-gapped/lessence/commit/e9cf051114c2e2569a4fbe158673521713e1f8c5))
* remove redundant_closure_for_method_calls allow, simplify 8 closures ([b038062](https://github.com/air-gapped/lessence/commit/b03806251b6297b1205bf03609595431aafbe9a2))
* remove single_char_pattern allow, use char literals for splits ([0d692c9](https://github.com/air-gapped/lessence/commit/0d692c956056fd22d051f30c5687f12e1adeb782))
* remove str_split_at_newline allow, use .lines() instead ([df5130c](https://github.com/air-gapped/lessence/commit/df5130c1908bf526f5c485f39c0e887cf70343ef))
* remove uninlined_format_args allow, fix all 233 instances ([086b62f](https://github.com/air-gapped/lessence/commit/086b62f59240c254134104f9ee42b9d09dc5e81b))
* remove unreadable_literal allow, add separators to large numbers ([6572dd4](https://github.com/air-gapped/lessence/commit/6572dd44778f4577c142934ff66b693543524803))
* resolve all clippy warnings, enforce in CI ([a15316b](https://github.com/air-gapped/lessence/commit/a15316b1858f3a5cef9b8b36eaa21ea71260f5ca))
* use GitHub App token for release-please, fix deny.toml schema ([c676a45](https://github.com/air-gapped/lessence/commit/c676a45342a392001a11f2252588ee7b986990e1))
* use oauth token instead of API key for release notes ([f610a99](https://github.com/air-gapped/lessence/commit/f610a9967c5401e8650f6427e10b53a109f8e491))


### Performance Improvements

* compile ANSI regex once via LazyLock instead of per-call ([9f7f8ee](https://github.com/air-gapped/lessence/commit/9f7f8ee5a1b1dcb30e67cebfe862532e222ddb49))

## [Unreleased]

### Added
- `--stats-json` flag for machine-readable JSON statistics on stderr
- `--top N` flag for frequency-sorted output (show N most common patterns)
- `--fail-on-pattern <regex>` for CI exit code gating (exit 1 on match, 2 on bad regex)
- `--completions <shell>` for shell completion generation (bash/zsh/fish/elvish/powershell)
- `-q` / `--quiet` as Unix-conventional alias for `--no-stats`
- File arguments: `lessence app.log` instead of stdin only
- Snapshot tests (insta) locking down output format
- Property-based tests (proptest) for normalizer invariants
- `cargo deny` for supply chain security (licenses, advisories, bans)
- `cargo fmt` enforcement in CI
- `cargo doc` with `-D warnings` in CI
- Weekly CI: `cargo machete` (unused deps) + `cargo update --dry-run` (outdated deps)
- Release workflow with prebuilt binaries for Linux/macOS/Windows
- `cargo-binstall` metadata for fast CI installation

### Changed
- Edition 2021 to 2024 (if-let chains, stricter patterns)
- Clippy pedantic enabled with `[lints.clippy]` in Cargo.toml
- `unsafe_code = "forbid"` enforced crate-wide
- ISO 8601 timestamps in stats output (`2025-04-01T12:00:00Z`)
- `cargo nextest` replaces `cargo test` in CI
- `taiki-e/install-action` replaces `cargo install` for CI tools
- Removed `RUSTFLAGS` env from CI (was invalidating Cargo cache)
- Stripped `rustfmt.toml` to stable-only options

### Removed
- `--max-tokens` flag (fake token counting was dishonest)
- `colored` dependency (unused)
- Token estimation from stats output (misleading approximations)

### Fixed
- 270+ clippy pedantic warnings fixed across 60 files
- 3 ANSI regex compiled per-call instead of once (now `LazyLock`)
- Hidden clippy lint masked by `RUSTFLAGS` cache invalidation
- Doc comments with unescaped `<EMAIL>` breaking rustdoc

## [0.1.0] - 2026-03-31

### Added
- Initial public release as `lessence`
- 16 pattern detectors (timestamp, hash, network, uuid, email, path, duration, json, kubernetes, http-status, brackets, key-value, process, quoted-string, name, decimal)
- Parallel processing via rayon
- `--essence` mode for temporal independence
- `--format markdown` output
- `--sanitize-pii` for email masking
- ReDoS protection on all regex patterns
- Security input limits (`--max-line-length`, `--max-lines`)

[Unreleased]: https://github.com/air-gapped/lessence/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/air-gapped/lessence/releases/tag/v0.1.0
