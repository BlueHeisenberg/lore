package relay

import (
	"fmt"
	"io"
)

// AdminSetPlan sets an account's plan directly in the DB (local ops path;
// no Stripe needed). Used by `lore-relay admin set-plan`.
func AdminSetPlan(dataDir, accountPub, plan string) error {
	st, err := OpenStore(dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	return st.SetPlan(accountPub, plan)
}

// AdminStats prints relay totals and per-account usage. Used by
// `lore-relay admin stats`.
func AdminStats(dataDir string, w io.Writer) error {
	st, err := OpenStore(dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	var accounts, devices, spaces, logRows int
	var logBytes, snapBytes int64
	row := func(q string, dst ...any) error { return st.db.QueryRow(q).Scan(dst...) }
	if err := row(`SELECT COUNT(*) FROM accounts`, &accounts); err != nil {
		return err
	}
	if err := row(`SELECT COUNT(*) FROM devices`, &devices); err != nil {
		return err
	}
	if err := row(`SELECT COUNT(*) FROM spaces`, &spaces); err != nil {
		return err
	}
	if err := row(`SELECT COUNT(*), COALESCE(SUM(size),0) FROM log_index`, &logRows, &logBytes); err != nil {
		return err
	}
	if err := row(`SELECT COALESCE(SUM(size),0) FROM snapshots`, &snapBytes); err != nil {
		return err
	}
	fmt.Fprintf(w, "accounts: %d  devices: %d  spaces: %d\n", accounts, devices, spaces)
	fmt.Fprintf(w, "log entries: %d (%d bytes)  snapshot bytes: %d\n", logRows, logBytes, snapBytes)

	rows, err := st.db.Query(`SELECT a.account_pub, COALESCE(a.handle,''), a.plan, u.used_bytes
		FROM accounts a JOIN account_usage u ON u.account_pub = a.account_pub
		ORDER BY u.used_bytes DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintf(w, "%-16s %-16s %-6s %s\n", "account", "handle", "plan", "used_bytes")
	for rows.Next() {
		var pub, handle, plan string
		var used int64
		if err := rows.Scan(&pub, &handle, &plan, &used); err != nil {
			return err
		}
		short := pub
		if len(short) > 16 {
			short = short[:16]
		}
		fmt.Fprintf(w, "%-16s %-16s %-6s %d\n", short, handle, plan, used)
	}
	return rows.Err()
}
