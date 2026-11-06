# Fuzz seeds

Committed starting inputs. `fuzz/corpus/` is gitignored — it grows to tens of
megabytes and is machine-specific — so CI begins every scheduled run with an
empty corpus and has to rediscover the shape of a valid input from random
bytes.

For `frame_header` that is fine: the target accepts anything 32 bytes long with
the right two leading bytes, which a fuzzer finds in moments.

For `create_body` it is not. That target's input has to survive
`serde_json::from_slice::<CreateRoomBody>` before it reaches the validation
worth testing, and random bytes are not going to produce a nested JSON object
with the right field names. Without a seed the run spends its whole budget
failing to parse.

The CI job copies these into the corpus before running. They are valid bodies,
one per TTL kind, and exist to get the fuzzer past the parser — not to be
interesting in themselves.

`evict_commit` has a seed for the same reason: its input has to get through a
length-prefixed config and a vote count before the votes are read. The seed is
a well-formed two-vote commit with a short tail.
