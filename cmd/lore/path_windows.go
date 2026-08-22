package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// addToPath appends dir to the *user* PATH in HKCU\Environment.
//
// Deliberately not setx: setx truncates the variable at 1024 characters and
// silently eats the tail of a long PATH. Read, append, write, nothing else -
// existing entries are never reordered or dropped.
func addToPath(_, dir string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open HKCU Environment key: %w", err)
	}
	defer k.Close()

	cur, valType, err := k.GetStringValue("Path")
	switch {
	case err == registry.ErrNotExist:
		// No user PATH at all yet. REG_EXPAND_SZ is what Windows itself
		// writes, so match it.
		cur, valType = "", registry.EXPAND_SZ
	case err != nil:
		return fmt.Errorf("read user Path: %w", err)
	}

	// The stored value may spell the entry with a variable
	// (%USERPROFILE%\bin); compare expanded so we don't add a duplicate.
	stored := cur
	if expanded, xerr := registry.ExpandString(cur); xerr == nil {
		stored = expanded
	}
	if pathContains(stored, dir) {
		fmt.Printf("path: %s is already on your user PATH (restart open shells to pick it up)\n", dir)
		return nil
	}

	next := dir
	if cur != "" {
		next = strings.TrimRight(cur, ";") + ";" + dir
	}
	// Preserve the value's type. Rewriting a REG_EXPAND_SZ Path as REG_SZ
	// would stop every %VAR% entry in it from expanding.
	if valType == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", next)
	} else {
		err = k.SetStringValue("Path", next)
	}
	if err != nil {
		return fmt.Errorf("write user Path: %w", err)
	}
	broadcastEnvChange()
	fmt.Printf("path: added %s to your user PATH - new shells will find lore; restart any that are already open\n", dir)
	return nil
}

var procSendMessageTimeoutW = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

// broadcastEnvChange tells running processes the environment moved, so a new
// shell sees the PATH without a logout. Best effort with a 1s timeout and
// SMTO_ABORTIFHUNG: a wedged window must not wedge lore.
func broadcastEnvChange() {
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001A
		smtoAbortIfHung = 0x0002
	)
	var result uintptr
	procSendMessageTimeoutW.Call(hwndBroadcast, wmSettingChange, 0,
		uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 1000, uintptr(unsafe.Pointer(&result)))
}
