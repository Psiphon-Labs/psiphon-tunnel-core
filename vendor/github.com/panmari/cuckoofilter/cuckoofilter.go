package cuckoo

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// maxCuckooKickouts is the maximum number of times reinsert
// is attempted.
const maxCuckooKickouts = 500

// Filter is a probabilistic counter.
type Filter struct {
	buckets []bucket
	count   uint
	// Bit mask set to len(buckets) - 1. As len(buckets) is always a power of 2,
	// applying this mask mimics the operation x % len(buckets).
	bucketIndexMask uint
}

// NewFilter returns a new cuckoofilter suitable for the given number of elements.
// When inserting more elements, insertion speed will drop significantly and insertions might fail altogether.
// A capacity of 1000000 is a normal default, which allocates
// about ~2MB on 64-bit machines.
func NewFilter(numElements uint) *Filter {
	numBuckets := getNextPow2(uint64(numElements / bucketSize))
	if float64(numElements)/float64(numBuckets*bucketSize) > 0.96 {
		numBuckets <<= 1
	}
	if numBuckets == 0 {
		numBuckets = 1
	}
	buckets := make([]bucket, numBuckets)
	return &Filter{
		buckets:         buckets,
		count:           0,
		bucketIndexMask: uint(len(buckets) - 1),
	}
}

// Lookup returns true if data is in the filter.
func (cf *Filter) Lookup(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	if b := cf.buckets[i1]; b.contains(fp) {
		return true
	}
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	b := cf.buckets[i2]
	return b.contains(fp)
}

// Reset removes all items from the filter, setting count to 0.
func (cf *Filter) Reset() {
	for i := range cf.buckets {
		cf.buckets[i].reset()
	}
	cf.count = 0
}

// Insert data into the filter. Returns false if insertion failed. In the resulting state, the filter
// * Might return false negatives
// * Deletes are not guaranteed to work
// To increase success rate of inserts, create a larger filter.
func (cf *Filter) Insert(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	if cf.insert(fp, i1) {
		return true
	}
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	if cf.insert(fp, i2) {
		return true
	}
	return cf.reinsert(fp, randi(i1, i2))
}

func (cf *Filter) insert(fp fingerprint, i uint) bool {
	if cf.buckets[i].insert(fp) {
		cf.count++
		return true
	}
	return false
}

func (cf *Filter) reinsert(fp fingerprint, i uint) bool {
	for k := 0; k < maxCuckooKickouts; k++ {
		j := rand.Intn(bucketSize)
		// Swap fingerprint with bucket entry.
		cf.buckets[i][j], fp = fp, cf.buckets[i][j]

		// Move kicked out fingerprint to alternate location.
		i = getAltIndex(fp, i, cf.bucketIndexMask)
		if cf.insert(fp, i) {
			return true
		}
	}
	return false
}

// Delete data from the filter. Returns true if the data was found and deleted.
func (cf *Filter) Delete(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	return cf.delete(fp, i1) || cf.delete(fp, i2)
}

func (cf *Filter) delete(fp fingerprint, i uint) bool {
	if cf.buckets[i].delete(fp) {
		cf.count--
		return true
	}
	return false
}

// Count returns the number of items in the filter.
func (cf *Filter) Count() uint {
	return cf.count
}

// LoadFactor returns the fraction slots that are occupied.
func (cf *Filter) LoadFactor() float64 {
	return float64(cf.count) / float64(len(cf.buckets)*bucketSize)
}

const bytesPerBucket = bucketSize * fingerprintSizeBits / 8

// Encode returns a byte slice representing a Cuckoofilter.
func (cf *Filter) Encode() []byte {
	bytes := make([]byte, 0, len(cf.buckets)*bytesPerBucket)
	for _, b := range cf.buckets {
		for _, f := range b {
			next := make([]byte, 2)
			binary.LittleEndian.PutUint16(next, uint16(f))
			bytes = append(bytes, next...)
		}
	}
	return bytes
}

// Decode returns a Cuckoofilter from a byte slice created using Encode.
func Decode(bytes []byte) (*Filter, error) {
	if len(bytes)%bucketSize != 0 {
		return nil, fmt.Errorf("bytes must to be multiple of %d, got %d", bucketSize, len(bytes))
	}
	numBuckets := len(bytes) / bytesPerBucket
	if numBuckets < 1 {
		return nil, fmt.Errorf("bytes can not be smaller than %d, size in bytes is %d", bytesPerBucket, len(bytes))
	}
	if getNextPow2(uint64(numBuckets)) != uint(numBuckets) {
		return nil, fmt.Errorf("numBuckets must to be a power of 2, got %d", numBuckets)
	}
	var count uint
	buckets := make([]bucket, numBuckets)
	for i, b := range buckets {
		for j := range b {
			var next []byte
			next, bytes = bytes[:2], bytes[2:]

			if fp := fingerprint(binary.LittleEndian.Uint16(next)); fp != 0 {
				buckets[i][j] = fp
				count++
			}
		}
	}
	return &Filter{
		buckets:         buckets,
		count:           count,
		bucketIndexMask: uint(len(buckets) - 1),
	}, nil
}
