---
status: in force
---

# A watched resource varies within one event

Lines that differ only in the resource a call acts on, such as
`"Failed to watch" err="nodes is forbidden ..."` and the same line for
`persistentvolumeclaims`, fold into one event with the resource as
`<VARIES>` and a count per resource on the line. The rule that allows it
(`MAX_PLAIN_WORD_DIFFS`, test `two_sentence_words_apart_is_another_event`)
stays as it is.

Why: nothing is hidden, because each resource is named with its count on
the shown line (principle 3, variation is on the line). The event, a
refused watch, is the same, and an agent reads which resources are refused
from the variant list.

Evidence: commit 9979c3c, goldens k8s_openebs and k8s_rook_ceph, the
fold-reviewer pass on that change.
