package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func WriteToFile(item io.WriterTo, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	_, err = item.WriteTo(file)
	if err != nil {
		return err
	}
	return file.Close()
}
