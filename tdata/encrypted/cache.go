package encrypted

import (
	"fmt"

	"github.com/0z0sk0/tdgodecrypt/qt"
	"github.com/0z0sk0/tdgodecrypt/tdata"
)

type ECache struct {
	Encrypted []byte
}

func ReadECache(rawtdf tdata.RawTDF) (ECache, error) {
	result := ECache{}
	streams, err := qt.ReadStreams(rawtdf.Data)
	if err != nil {
		return result, fmt.Errorf("could not get mapped: %v", err)
	}
	if len(streams) != 1 {
		return result, fmt.Errorf("can only call ToMapped on files with a single stream")
	}
	result.Encrypted = streams[0]
	return result, err
}
