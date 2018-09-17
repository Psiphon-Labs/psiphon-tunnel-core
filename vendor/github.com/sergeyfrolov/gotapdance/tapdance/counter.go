package tapdance

import "sync"

// CounterUint64 is a goroutine-safe uint64 counter.
// Wraps, if underflows/overflows.
type CounterUint64 struct {
	sync.Mutex
	value uint64
}

// Inc increases the counter and returns resulting value
func (c *CounterUint64) Inc() uint64 {
	c.Lock()
	defer c.Unlock()
	if c.value == ^uint64(0) {
		// if max
		c.value = 0
	} else {
		c.value++
	}
	return c.value
}

// GetAndInc returns current value and then increases the counter
func (c *CounterUint64) GetAndInc() uint64 {
	c.Lock()
	defer c.Unlock()
	if c.value == ^uint64(0) {
		// if max
		c.value = 0
	}
	retVal := c.value
	c.value++
	return retVal
}

// Dec decrements the counter and returns resulting value
func (c *CounterUint64) Dec() uint64 {
	c.Lock()
	defer c.Unlock()
	if c.value == 0 {
		c.value = ^uint64(0)
	} else {
		c.value--
	}
	return c.value
}

// Get returns current counter value
func (c *CounterUint64) Get() (value uint64) {
	c.Lock()
	defer c.Unlock()
	value = c.value
	return
}
