package bypass

import (
	"crypto/md5"
	"io"
	"math/rand"
)

// ReaderReaderAt has the methods of an io.Reader and an io.ReaderAt
type ReaderReaderAt interface {
	io.Reader
	io.ReaderAt
}

// PartialChecksum computes a checksum based on three 8KB chunks from the
// beginning, middle, and end of the file
func PartialChecksum(reader ReaderReaderAt, filesize int64) ([]byte, error) {
	// Checksum based on 8KB chunks
	var chunksize int64 = 8192

	digest := md5.New()
	buf := make([]byte, chunksize)

	// Chunk from beginning of the file
	if _, err := reader.Read(buf); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(digest, string(buf)); err != nil {
		return nil, err
	}

	// Chunk from random location that does not overlap with beginning or end of file
	if filesize-chunksize*3 > 0 {
		rand.Seed(filesize)
		offset := chunksize + rand.Int63n(filesize-2*chunksize)
		if _, err := reader.ReadAt(buf, offset); err != nil {
			return nil, err
		}
		if _, err := io.WriteString(digest, string(buf)); err != nil {
			return nil, err
		}
	}

	// Chunk from end of the file
	if filesize > chunksize {
		if _, err := reader.ReadAt(buf, filesize-chunksize); err != nil {
			return nil, err
		}
		if _, err := io.WriteString(digest, string(buf)); err != nil {
			return nil, err
		}
	}

	return digest.Sum(nil), nil
}
