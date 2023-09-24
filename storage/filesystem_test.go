package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewFileSystem(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			path    string
			options []FileSystemOption
		}
		want FileSystem
	}{
		{
			name: "New File storage",
			input: struct {
				path    string
				options []FileSystemOption
			}{
				path: filepath.Join(_testFullPath),
			},
			want: FileSystem{
				path: filepath.Join(_testFullPath),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NewFileSystem(test.input.path, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(FileSystem{})); diff != "" {
				t.Errorf("NewFile() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestFileSystem_Save(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			path            string
			data            []byte
			dirShouldExist  bool
			fileShouldExist bool
		}
		want    []byte
		wantErr error
	}{
		{
			name: "Save contents",
			input: struct {
				path            string
				data            []byte
				dirShouldExist  bool
				fileShouldExist bool
			}{
				path:            filepath.Join("../", _testRoot, _testDir, _testFile),
				data:            []byte(`test`),
				dirShouldExist:  true,
				fileShouldExist: true,
			},
			want:    []byte(`test`),
			wantErr: nil,
		},
		{
			name: "Save contents - file does not exist",
			input: struct {
				path            string
				data            []byte
				dirShouldExist  bool
				fileShouldExist bool
			}{
				path: filepath.Join("../", _testRoot, _testDir, _testFile),
				data: []byte(`test`),
			},
			want:    nil,
			wantErr: ErrStorageSourceNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupFileSystemTest(test.input.dirShouldExist, test.input.fileShouldExist)
			defer cleanupFileSystemTest(test.input.dirShouldExist, test.input.fileShouldExist)
			stg := FileSystem{
				path: test.input.path,
			}

			gotErr := stg.Save(test.input.data)

			var got []byte
			if gotErr == nil {
				got, _ = os.ReadFile(test.input.path)
			}

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Save() = unexpected result (-want, +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Save() = unexpected error (-want +got)\n%s\n", diff)
			}

		})
	}
}

func setupFileSystemTest(dirShouldExist, fileShouldExist bool) {
	if dirShouldExist {
		_ = os.MkdirAll(filepath.Join("../", _testRoot, _testDir), 0700)
	}
	if fileShouldExist && dirShouldExist {
		_, _ = os.OpenFile(filepath.Join("../", _testFullPath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)

	}
}

func cleanupFileSystemTest(dirShouldExist, fileShouldExist bool) {
	os.Remove(filepath.Join("../", _testFullPath))
	os.RemoveAll(filepath.Join("../", _testRoot, _testDir))
}

var (
	_testRoot     = "testdata"
	_testDir      = "test"
	_testFile     = "secman.db"
	_testFullPath = filepath.Join(_testRoot, _testDir, _testFile)
)
