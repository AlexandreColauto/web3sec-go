package taxonomy

// difflib port (SequenceMatcher / get_close_matches): class_report's
// suggestions come from difflib.get_close_matches, so the suggestion list
// is part of the byte-exact contract. Split from taxonomy.go (same package).
import (
	"sort"
)

// ---- difflib (SequenceMatcher / get_close_matches) ----------------------
//
// class_report's suggestions come from difflib.get_close_matches, so the
// suggestion list is part of the byte-exact contract. This is a faithful port
// of CPython 3.14's difflib for the no-junk case get_close_matches uses
// (SequenceMatcher() with isjunk=None, autojunk=True).

// seqRatio is SequenceMatcher(None, a, b).ratio(): 2*M/T over the rune
// positions the longest-matching-block recursion covers.
func seqRatio(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	return calcRatio(matchedRunes(ra, rb), len(ra)+len(rb))
}

// quickRatio is quick_ratio: the multiset-intersection upper bound.
func quickRatio(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	full := make(map[rune]int, len(rb))
	for _, r := range rb {
		full[r]++
	}
	avail := make(map[rune]int, len(ra))
	matches := 0
	for _, r := range ra {
		numb, ok := avail[r]
		if !ok {
			numb = full[r]
		}
		avail[r] = numb - 1
		if numb > 0 {
			matches++
		}
	}
	return calcRatio(matches, len(ra)+len(rb))
}

// realQuickRatio is real_quick_ratio: can't have more matches than the
// shorter sequence has elements.
func realQuickRatio(a, b string) float64 {
	la, lb := len([]rune(a)), len([]rune(b))
	return calcRatio(min(la, lb), la+lb)
}

// calcRatio is difflib._calculate_ratio.
func calcRatio(matches, length int) float64 {
	if length > 0 {
		return 2.0 * float64(matches) / float64(length)
	}
	return 1.0
}

// matchedRunes is get_matching_blocks' total match size: the recursive
// longest-match partition, which is all ratio() sums.
func matchedRunes(a, b []rune) int {
	b2j := buildB2J(b)
	total := 0
	queue := [][4]int{{0, len(a), 0, len(b)}}
	for len(queue) > 0 {
		q := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		i, j, k := findLongestMatch(a, b, b2j, q[0], q[1], q[2], q[3])
		if k == 0 {
			continue
		}
		total += k
		if q[0] < i && q[2] < j {
			queue = append(queue, [4]int{q[0], i, q[2], j})
		}
		if i+k < q[1] && j+k < q[3] {
			queue = append(queue, [4]int{i + k, q[1], j + k, q[3]})
		}
	}
	return total
}

// buildB2J is SequenceMatcher's b2j index with autojunk: elements that appear
// more than n//100+1 times in a sequence of 200+ runes are "popular" and drop
// out of the index.
func buildB2J(b []rune) map[rune][]int {
	idx := make(map[rune][]int)
	for i, r := range b {
		idx[r] = append(idx[r], i)
	}
	if len(b) < 200 {
		return idx
	}
	ntest := len(b)/100 + 1
	for r, positions := range idx {
		if len(positions) > ntest {
			delete(idx, r)
		}
	}
	return idx
}

// findLongestMatch is SequenceMatcher.find_longest_match for the no-junk
// case: of all maximal matching blocks, the one that starts earliest in a,
// and of those the one that starts earliest in b.
func findLongestMatch(a, b []rune, b2j map[rune][]int,
	alo, ahi, blo, bhi int) (int, int, int) {
	besti, bestj, bestsize := alo, blo, 0
	j2len := map[int]int{}
	for i := alo; i < ahi; i++ {
		newj2len := make(map[int]int, len(j2len)+1)
		for _, j := range b2j[a[i]] {
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			newj2len[j] = k
			if k > bestsize {
				besti, bestj, bestsize = i-k+1, j-k+1, k
			}
		}
		j2len = newj2len
	}
	for besti > alo && bestj > blo && a[besti-1] == b[bestj-1] {
		besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
	}
	for besti+bestsize < ahi && bestj+bestsize < bhi &&
		a[besti+bestsize] == b[bestj+bestsize] {
		bestsize++
	}
	return besti, bestj, bestsize
}

// closeMatches is difflib.get_close_matches(word, possibilities, n, cutoff):
// the best (no more than n) matches at or above cutoff, most similar first,
// ties broken by possibilities order (heapq.nlargest is a stable sort).
func closeMatches(word string, possibilities []string, n int, cutoff float64) []string {
	type cand struct {
		score float64
		index int
	}
	var cands []cand
	for i, x := range possibilities {
		if realQuickRatio(x, word) < cutoff {
			continue
		}
		if quickRatio(x, word) < cutoff {
			continue
		}
		if r := seqRatio(x, word); r >= cutoff {
			cands = append(cands, cand{score: r, index: i})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})
	if len(cands) > n {
		cands = cands[:n]
	}
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = possibilities[c.index]
	}
	return out
}
