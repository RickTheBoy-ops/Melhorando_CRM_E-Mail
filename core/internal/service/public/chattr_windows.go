// +build windows

package public

import (
	"errors"
	"os"
)

// Change file or directory attributes (Windows implementation)
// This is a no-op on Windows as it doesn't support Unix file attributes
func Chattr(path string, attr string) error {
	return ChattrRecursive(path, attr)
}

// Change file or directory attributes (recursive) - Windows implementation
// On Windows, this function validates parameters but doesn't actually change attributes
// since Windows doesn't support Unix-style file attributes (immutable, append-only, etc.)
func ChattrRecursive(path string, attr string) error {
	// Validate parameters
	if len(attr) != 2 || (attr[0] != '+' && attr[0] != '-') {
		return errors.New("invalid attr: " + attr)
	}

	if attr[1] != 'i' && attr[1] != 'a' && attr[1] != 'd' && attr[1] != 's' && attr[1] != 'c' {
		return errors.New("invalid attr: " + attr)
	}

	// Check if file exists
	if !FileExists(path) {
		return errors.New("file not exists: " + path)
	}

	// For directories, recursively check subdirectories
	if IsDir(path) {
		ds, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		for _, d := range ds {
			err = ChattrRecursive(path+"/"+d.Name(), attr)
			if err != nil {
				return err
			}
		}
	}

	// On Windows, we don't actually set the attributes since they're Unix-specific
	// Just return success to maintain compatibility
	return nil
}