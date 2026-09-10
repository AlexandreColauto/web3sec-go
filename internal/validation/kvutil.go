package validation

// KV list surgery helpers — the one canonical home for the object-field
// set/append pattern the framework uses on every artifact it builds.
// (These replaced 17 identical per-package copies and five subtly-renamed
// twins; behavior is unchanged: replace-or-append preserves insertion
// order, and a default never overwrites an existing key, not even a null.)

// SetOrAppend sets o[key] = v in an object's KV list, appending the pair
// when the key is absent. The slice is modified in place and returned.
func SetOrAppend(o []KV, key string, v Value) []KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, KV{K: key, V: v})
}

// SetDefault appends o[key] = v only when the key is absent.
func SetDefault(o []KV, key string, v Value) []KV {
	for _, kv := range o {
		if kv.K == key {
			return o
		}
	}
	return append(o, KV{K: key, V: v})
}
