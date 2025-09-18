// +build !windows

package public

import (
	"errors"
	"os"
	"github.com/g0rbe/go-chattr"
)

// Change file or directory attributes (Unix implementation)
func Chattr(path string, attr string) error {
	return ChattrRecursive(path, attr)
}

// Change file or directory attributes (recursive) - Unix implementation
func ChattrRecursive(path string, attr string) error {
	// Check if attr is valid
	if len(attr) != 2 || (attr[0] != '+' && attr[0] != '-') {
		return errors.New("invalid attr: " + attr)
	}

	if attr[1] != 'i' && attr[1] != 'a' && attr[1] != 'd' && attr[1] != 's' && attr[1] != 'c' {
		return errors.New("invalid attr: " + attr)
	}

	// File does not exist
	if !FileExists(path) {
		return errors.New("file not exists: " + path)
	}

	// Directory
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

	// Change file attributes
	fp, err := os.Open(path)

	if err != nil {
		return err
	}

	defer fp.Close()

	var flag int32

	switch attr[1] {
	case 'i':
		flag = chattr.FS_IMMUTABLE_FL
	case 'a':
		flag = chattr.FS_APPEND_FL
	case 'd':
		flag = chattr.FS_NODUMP_FL
	case 's':
		flag = chattr.FS_SYNC_FL
	case 'c':
		flag = chattr.FS_COMPR_FL
	}

	if attr[0] == '+' {
		return chattr.SetAttr(fp, flag)
	}

	return chattr.UnsetAttr(fp, flag)
}