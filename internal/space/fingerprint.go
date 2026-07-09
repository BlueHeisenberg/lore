package space

import (
	"crypto/sha256"
	"strings"
)

// fingerprintWords is a 256-word list (distinct, short, easy to say over a
// shoulder or a call) used to render invite fingerprints. Index = one byte.
var fingerprintWords = [256]string{
	"acid", "acorn", "actor", "alarm", "alien", "amber", "anchor", "angle",
	"ankle", "antler", "apple", "apron", "arch", "arrow", "atlas", "attic",
	"autumn", "avocado", "axis", "badge", "bagel", "bamboo", "banjo", "barn",
	"basket", "beacon", "beetle", "bell", "berry", "bishop", "bison", "blade",
	"blanket", "blossom", "bolt", "bonfire", "boot", "bottle", "boulder", "bow",
	"box", "branch", "brass", "bread", "brick", "bridge", "broom", "brush",
	"bubble", "bucket", "budgie", "bugle", "bunker", "butter", "button", "cabin",
	"cactus", "camel", "camera", "canal", "candle", "canoe", "canyon", "carpet",
	"carrot", "castle", "cedar", "cellar", "chalk", "cheese", "cherry", "chess",
	"chime", "chisel", "cider", "cinder", "circle", "citrus", "clay", "cliff",
	"clock", "cloud", "clover", "cobalt", "coconut", "comet", "compass", "copper",
	"coral", "cotton", "cradle", "crane", "crater", "crayon", "cricket", "crown",
	"crystal", "cube", "cypress", "daisy", "deer", "delta", "denim", "desk",
	"dew", "dice", "dime", "dingo", "dome", "donkey", "door", "dragon",
	"drum", "duck", "dune", "eagle", "easel", "echo", "eel", "elbow",
	"elk", "ember", "engine", "fabric", "falcon", "feather", "fern", "ferry",
	"fiddle", "fig", "finch", "flag", "flame", "flint", "flute", "foam",
	"forest", "fossil", "fox", "frost", "galaxy", "garden", "garlic", "gecko",
	"geyser", "ginger", "glacier", "glass", "globe", "goat", "gold", "gondola",
	"goose", "granite", "grape", "gravel", "guitar", "hammer", "harbor", "harp",
	"hazel", "helmet", "heron", "hill", "hinge", "honey", "hook", "hornet",
	"horse", "hourglass", "husky", "igloo", "iguana", "indigo", "iris", "iron",
	"island", "ivory", "ivy", "jade", "jaguar", "jasmine", "jelly", "jigsaw",
	"jungle", "juniper", "kayak", "kettle", "kiwi", "knight", "koala", "ladder",
	"lagoon", "lantern", "lava", "leaf", "lemon", "lens", "lily", "lime",
	"lion", "lizard", "llama", "lobster", "locket", "log", "lotus", "magnet",
	"mango", "maple", "marble", "mask", "meadow", "melon", "mesa", "mint",
	"mirror", "monsoon", "moon", "moss", "moth", "mountain", "mule", "mustard",
	"nectar", "needle", "nickel", "night", "nutmeg", "oak", "oasis", "ocean",
	"olive", "onion", "opal", "orange", "orbit", "orchid", "otter", "owl",
	"oyster", "paddle", "pagoda", "palm", "panda", "paper", "parrot", "peach",
	"pearl", "pebble", "pelican", "penguin", "pepper", "piano", "pine", "planet",
}

// FingerprintWords derives the invite-confirmation fingerprint from the two
// account signing pubkeys (hex): SHA-256 over the sorted pubs, first four
// bytes mapped to words. Both sides compute it independently; matching words
// prove both humans see the same two keys (no MITM key substitution).
func FingerprintWords(accountPubA, accountPubB string) string {
	lo, hi := accountPubA, accountPubB
	if lo > hi {
		lo, hi = hi, lo
	}
	sum := sha256.Sum256([]byte(lo + hi))
	parts := make([]string, 4)
	for i := 0; i < 4; i++ {
		parts[i] = fingerprintWords[sum[i]]
	}
	return strings.Join(parts, "-")
}
