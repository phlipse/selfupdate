package selfupdate

import (
	"fmt"
	"io"
	"os"
)

// smallest known ELF has 45 bytes, PE executable 97 bytes
const minFileSize = 45

// FileSource provide a Source that will copy the update from a local file path.
// It is expecting the signature file to be located at ${FILEPATH}.ed25519
type FileSource struct {
	basePath string
}

var _ Source = (*FileSource)(nil)

// NewFileSource provides a selfupdate.Source that will fetch the specified file path
// for update and signature using the standard filesystem access. To help into providing
// cross platform application, the base is actually a Go Template string where the
// following parameter are recognized:
// {{.OS}} will be filled by the runtime OS name
// {{.Arch}} will be filled by the runtime Arch name
// {{.Ext}} will be filled by the executable expected extension for the OS
func NewFileSource(base string) Source {
	base = replaceURLTemplate(base) // TODO should be refactored to generic replacement function

	return &FileSource{basePath: base}
}

// Get will return if it succeed an io.ReaderCloser to the new executable and its length
func (f *FileSource) Get(v *Version) (io.ReadCloser, int64, error) {
	updateInfo, err := os.Stat(f.basePath)
	if err != nil {
		return nil, 0, err
	}
	if updateInfo.IsDir() || updateInfo.Size() == 0 {
		return nil, 0, fmt.Errorf("file path does not point to update: %v", f.basePath)
	} else if updateInfo.Size() < minFileSize {
		return nil, 0, fmt.Errorf("update file too small")
	}

	updateFile, err := os.Open(f.basePath)
	if err != nil {
		return nil, 0, err
	}

	return updateFile, updateInfo.Size(), nil
}

// GetSignature will return the content of  ${FILEPATH}.ed25519
func (f *FileSource) GetSignature() ([64]byte, error) {
	sigInfo, err := os.Stat(f.basePath + ".ed25519")
	if err != nil {
		return [64]byte{}, err
	}
	if sigInfo.IsDir() {
		return [64]byte{}, fmt.Errorf("file path does not point to signature file: %v", f.basePath+".ed25519")
	}
	if sigInfo.Size() != 64 {
		return [64]byte{}, fmt.Errorf("ed25519 signature must be 64 bytes long and was %v", sigInfo.Size())
	}

	sig, err := os.ReadFile(f.basePath + ".ed25519")
	if err != nil {
		return [64]byte{}, err
	}

	r := [64]byte{}
	copy(r[:], sig)

	return r, nil
}

// LatestVersion will return the update files last modified time
func (f *FileSource) LatestVersion() (*Version, error) {
	updateInfo, err := os.Stat(f.basePath)
	if err != nil {
		return nil, err
	}
	modTime := updateInfo.ModTime()

	// TODO should support for .version file which contains the app version

	return &Version{Date: modTime}, nil
}
