// rar compression module
// @author <2024-06-09>

package compress

import (
	"errors"
	"fmt"
	"github.com/nwaples/rardecode"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// defaultRarUnpacker default rar decompressor
	defaultRarUnpacker = NewRarUnpacker(-1)
)

// RarUnpacker rar decompressor
type RarUnpacker struct {
	mutex   sync.Mutex // mutex
	quota   int64      // decompressed file size limit, -1 for unlimited
	written int64      // size of already decompressed file
}

// NewRarUnpacker creates a rar decompressor
func NewRarUnpacker(quota int64) *RarUnpacker {
	return &RarUnpacker{quota: quota}
}

// SetQuota sets the decompressed file size limit
func (r *RarUnpacker) SetQuota(quota int64) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.quota = quota
}

// incWritten increases the size of already decompressed file
func (r *RarUnpacker) incWritten(n int64) (err error) {
	// if no limit is set, do nothing
	if r.quota < 0 {
		return nil
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.written += n

	// check if exceeds the limit
	if r.quota > -1 && r.written > r.quota {
		err = errors.New("disk quota exceeded")
		return
	}

	return nil
}

// Decompress decompresses a rar file
func (r *RarUnpacker) Decompress(src, dst string) error {
	// get absolute path of decompression target
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}

	// open the rar file
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	// create a new rar reader
	rr, err := rardecode.NewReader(file, "")
	if err != nil {
		return err
	}

	// extract each file
	for {
		header, err := rr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// remove ../ from filename to prevent path traversal
		arcName := filepath.ToSlash(filepath.Clean(header.Name))
		if strings.Contains(arcName, "../") {
			arcName = strings.Replace(arcName, "../", "", -1)
		}

		filename := filepath.Join(dst, arcName)

		// get absolute path of the file
		filenameAbs, err := filepath.Abs(filename)
		if err != nil {
			return err
		}

		// check if the file is under the decompression target path
		if !strings.HasPrefix(filenameAbs, dstAbs) {
			return errors.New("illegal file path: " + filename)
		}

		// check if it's a directory
		// if it's a directory, create it and skip
		if header.IsDir {
			err = os.MkdirAll(filename, 0755)
			if err != nil {
				return err
			}
			continue
		}

		// create directory
		err = os.MkdirAll(filepath.Dir(filename), 0755)
		if err != nil {
			return err
		}

		// create file
		outFile, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}

		err = func() error {
			defer outFile.Close()

			var n int64
			n, err = io.Copy(outFile, rr)
			if err != nil {
				return err
			}

			// increase the size of already decompressed file
			return r.incWritten(n)
		}()

		if err != nil {
			return err
		}
	}

	return nil
}

// Compress compresses files or directories into a rar archive using external rar command
func (r *RarUnpacker) Compress(dst string, srcList ...string) error {
	// check if 'rar' command exists
	_, err := exec.LookPath("rar")
	if err != nil {
		return errors.New("rar command not found, please install it first")
	}

	// ensure dst ends with .rar
	if !strings.HasSuffix(strings.ToLower(dst), ".rar") {
		dst += ".rar"
	}

	// get absolute paths to avoid path traversal issues
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}

	// prepare command arguments
	args := []string{"a", "-ep1", "-r"}

	// add destination file
	args = append(args, dstAbs)

	// validate each source and add it to command
	for _, src := range srcList {
		srcAbs, err := filepath.Abs(src)
		if err != nil {
			return err
		}

		// make sure source exists
		if _, err := os.Stat(srcAbs); err != nil {
			return fmt.Errorf("source file/directory does not exist: %s", src)
		}

		// add source to arguments
		args = append(args, srcAbs)
	}

	// create command
	cmd := exec.Command("rar", args...)

	// run command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rar compression failed: %s - %s", err, string(output))
	}

	// verify the file was created
	if _, err := os.Stat(dstAbs); err != nil {
		return errors.New("rar file was not created successfully")
	}

	return nil
}

// Unrar rar decompression
// @author <2024-06-09>
func Unrar(src, dst string) error {
	return defaultRarUnpacker.Decompress(src, dst)
}

// Rar compresses files or directories into a rar archive
// @author <2024-06-09>
func Rar(dst string, srcList ...string) error {
	return defaultRarUnpacker.Compress(dst, srcList...)
}

// UnrarWithExternalCommand decompresses a rar file using external rar command
// This is an alternative method using the external rar command
func UnrarWithExternalCommand(src, dst string) error {
	// check if 'unrar' command exists
	_, err := exec.LookPath("unrar")
	if err != nil {
		return errors.New("unrar command not found, please install it first")
	}

	// get absolute paths
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}

	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}

	// ensure destination directory exists
	if err := os.MkdirAll(dstAbs, 0755); err != nil {
		return err
	}

	// use extract command with full path
	cmd := exec.Command("unrar", "x", "-o+", srcAbs, dstAbs)

	// run command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unrar extraction failed: %s - %s", err, string(output))
	}

	return nil
}
