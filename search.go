package lore

import (
	"context"
	"strings"
	"unicode"

	"github.com/BlueHeisenberg/lore/internal/store"
)

// DefaultSearchLimit is what SearchOpts.Limit <= 0 means.
const DefaultSearchLimit = 8

// SearchOpts filter a search. The zero value searches every space with no
// filters and DefaultSearchLimit results.
type SearchOpts struct {
	// Spaces restricts the search to these space ids. Empty means every space
	// the store holds — which is a decision, not a default: a caller that
	// makes an authorization decision should pass the resolved set and never
	// rely on emptiness meaning what it wants.
	Spaces []string

	// Domain matches exactly, e.g. "ops/deploy".
	Domain string

	// Marker matches one marker, in either spelling: "IMPORTANT" and
	// "[IMPORTANT]" are the same filter.
	Marker string

	Confidence Confidence

	// Limit caps the results. <= 0 means DefaultSearchLimit.
	Limit int
}

// SearchResult is a whole entry plus the matching fragment of its body.
type SearchResult struct {
	Entry

	// Snippet is roughly twelve tokens around the match, with matched terms
	// wrapped in square brackets and "…" where text was elided. It is for
	// showing a human why an entry matched; Entry.Body is the entry.
	Snippet string
}

// Search runs a full-text match over title, body and domain, best matches
// first, excluding deleted entries.
//
// The match is conjunctive over bare words and nothing more: no operators, no
// stemming, no prefix matching, no stopwords. Every word in the query must
// appear in the entry. Punctuation is a separator. Passing a person's
// sentence through unchanged will usually match nothing; turning a sentence
// into queries is the caller's job, and Terms reports what a given text
// reduces to.
//
// A query with no searchable words returns no results and no error.
func (s *Store) Search(ctx context.Context, query string, o SearchOpts) ([]SearchResult, error) {
	if o.Confidence != "" && !o.Confidence.Valid() {
		return nil, invalid("confidence %q", o.Confidence)
	}
	var rs []store.SearchResult
	err := s.do(ctx, func() error {
		var err error
		rs, err = s.st.Search(query, store.SearchOpts{
			Spaces:     o.Spaces,
			Domain:     o.Domain,
			Marker:     o.Marker,
			Confidence: string(o.Confidence),
			Limit:      o.Limit,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return nil, nil
	}
	out := make([]SearchResult, len(rs))
	for i, r := range rs {
		out[i] = SearchResult{Entry: entryOf(r.Entry), Snippet: r.Snippet}
	}
	return out, nil
}

// Terms reduces text to the words Search will actually match on.
//
// lore's search is a conjunctive full-text match over bare words, and this is
// what it does to a query — measured against a real store rather than
// inferred:
//
//   - Everything that is not a letter or a digit is a separator, so
//     "boiler, service", "boiler service" and `"boiler service"` are the
//     same query.
//   - It is case-insensitive.
//   - There are no operators. "boiler AND service" finds nothing, because
//     "and" is just another word every entry must contain; "boiler OR
//     service" likewise. The trailing "*" of "boiler*" is stripped rather
//     than honoured — it finds what "boiler" finds, and "boil*" finds
//     nothing at all. There is no prefix matching.
//   - There is no stemming. An entry saying "service" is not found by
//     "servicing".
//   - There are no stopwords, and no minimum term length that matters here:
//     "is" and "the" match entries containing them, and rule out entries
//     that do not.
//   - Every term must be present. One absent word — "what", in "what is the
//     boiler service code" — excludes an entry that holds the answer.
//
// Terms exists so that a caller can reason in the units lore counts in.
// Matching a whole word rather than a substring is part of that: lore
// tokenises "quillfeather921834100" as one word, so "quillfeather" does not
// find it.
func Terms(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}
