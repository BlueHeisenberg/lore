package lore

import (
	"errors"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/store"
)

// The error contract. Every error this package returns satisfies errors.Is
// against exactly one of these, or is a context error (context.Canceled /
// context.DeadlineExceeded) from the caller's own ctx.
//
// Errors carry the space or entry id when that helps a reader; they never
// carry an entry's title or body, because an error string is the one place a
// private knowledge store leaks into a log.
var (
	// ErrNotFound: no entry with that id, or it was deleted. A tombstone is
	// not returned to a reader on any path.
	ErrNotFound = errors.New("lore: entry not found")

	// ErrSpaceNotFound: this store holds no such space. Distinct from
	// ErrNotFound because it is almost always a configuration fault rather
	// than a missing record — and because being locally present IS the
	// membership check: a space this store does not hold was never synced
	// here.
	ErrSpaceNotFound = errors.New("lore: space not found")

	// ErrWrongSpace: the entry exists, in a different space than the one
	// named. Entry ids are global to a store, so every operation naming both
	// an id and a space refuses the mismatch rather than acting on the other
	// space. Nothing was read out and nothing was written.
	ErrWrongSpace = errors.New("lore: entry is not in that space")

	// ErrNotWriter: this store's account holds only the reader role in that
	// shared space and may not author into it. Nothing was written.
	ErrNotWriter = errors.New("lore: not a writer of the space")

	// ErrUserModel: profile/ and feedback/ entries are the user model. They
	// never leave the personal space, on any path.
	ErrUserModel = errors.New("lore: user-model entry cannot leave the personal space")

	// ErrInvalidArgument: the call could not be formed — a missing required
	// field, or a confidence or origin outside the vocabulary. A programming
	// error; nothing was written.
	ErrInvalidArgument = errors.New("lore: invalid argument")

	// ErrReadOnly: a write on a store opened with Options.ReadOnly, which
	// loads no device key and therefore cannot sign.
	ErrReadOnly = errors.New("lore: store is read-only")

	// ErrClosed: any call after Close.
	ErrClosed = errors.New("lore: store is closed")

	// ErrNoAccount: the home has no account.json or device.json. Run
	// `lore init`. Open-time only.
	ErrNoAccount = errors.New("lore: home is not initialised")

	// ErrSchemaTooNew: the database was written by a newer lore than this
	// build. Open-time only, and it refuses rather than proceeding: an older
	// build silently reading a newer schema's columns corrupts. See the
	// version-skew note in the package doc.
	ErrSchemaTooNew = errors.New("lore: database schema is newer than this build")

	// ErrBusy: another process held the database past the retry budget. lore
	// retries internally first (see Options.Home and the package doc on
	// concurrency); when it does return ErrBusy the call did nothing and may
	// be retried.
	ErrBusy = errors.New("lore: store is busy")
)

// wrap maps an internal/store error onto this package's contract. Anything
// unrecognised is returned as-is: inventing a sentinel for an unknown failure
// would be a worse lie than an honest opaque error.
//
// Order matters: ErrSpaceNotFound wraps store.ErrNotFound, so it is tested
// first.
func wrap(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrSpaceNotFound):
		return ErrSpaceNotFound
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrWrongSpace):
		return ErrWrongSpace
	case errors.Is(err, store.ErrNotWriter):
		return ErrNotWriter
	case errors.Is(err, store.ErrUserModel):
		return ErrUserModel
	case errors.Is(err, store.ErrNoSigner):
		return ErrReadOnly
	case errors.Is(err, store.ErrSchemaTooNew):
		return fmt.Errorf("%w: %s", ErrSchemaTooNew, err)
	case store.IsBusy(err):
		return ErrBusy
	}
	return err
}

// invalid builds an ErrInvalidArgument with a reason.
func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidArgument}, a...)...)
}
