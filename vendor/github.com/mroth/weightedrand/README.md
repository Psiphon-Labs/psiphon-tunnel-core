# weightedrand :balance_scale:

[![PkgGoDev](https://pkg.go.dev/badge/github.com/mroth/weightedrand)](https://pkg.go.dev/github.com/mroth/weightedrand)
[![CodeFactor](https://www.codefactor.io/repository/github/mroth/weightedrand/badge)](https://www.codefactor.io/repository/github/mroth/weightedrand)
[![Build Status](https://github.com/mroth/weightedrand/workflows/test/badge.svg)](https://github.com/mroth/weightedrand/actions)
[![codecov](https://codecov.io/gh/mroth/weightedrand/branch/master/graph/badge.svg)](https://codecov.io/gh/mroth/weightedrand)

> Fast weighted random selection for Go.

Randomly selects an element from some kind of list, where the chances of each
element to be selected are not equal, but rather defined by relative "weights"
(or probabilities). This is called weighted random selection.

## Usage

```go
import (
    /* ...snip... */
    wr "github.com/mroth/weightedrand"
)

func main() {
    rand.Seed(time.Now().UTC().UnixNano()) // always seed random!

    chooser, _ := wr.NewChooser(
        wr.Choice{Item: "🍒", Weight: 0},
        wr.Choice{Item: "🍋", Weight: 1},
        wr.Choice{Item: "🍊", Weight: 1},
        wr.Choice{Item: "🍉", Weight: 3},
        wr.Choice{Item: "🥑", Weight: 5},
    )
    /* The following will print 🍋 and 🍊 with 0.1 probability, 🍉 with 0.3
    probability, and 🥑 with 0.5 probability. 🍒 will never be printed. (Note
    the weights don't have to add up to 10, that was just done here to make the
    example easier to read.) */
    result := chooser.Pick().(string)
    fmt.Println(result)
}
```

## Performance

The existing Go library that has a comparable implementation of this is
[`github.com/jmcvetta/randutil`][1], which optimizes for the single operation
case. In contrast, this library creates a presorted cache optimized for binary
search, allowing repeated selections from the same set to be significantly
faster, especially for large data sets.

[1]: https://github.com/jmcvetta/randutil

Comparison of this library versus `randutil.ChooseWeighted` on my workstation.
For repeated samplings from large collections, `weightedrand` will be much
quicker:

| Num choices |     `randutil` | `weightedrand` | `weightedrand -cpu=8`* |
| ----------: | -------------: | -------------: | ---------------------: |
|          10 |      201 ns/op |       38 ns/op |              2.9 ns/op |
|         100 |      267 ns/op |       51 ns/op |              4.1 ns/op |
|       1,000 |     1012 ns/op |       67 ns/op |              5.4 ns/op |
|      10,000 |     8683 ns/op |       83 ns/op |              6.9 ns/op |
|     100,000 |   123500 ns/op |      105 ns/op |             12.0 ns/op |
|   1,000,000 |  2399614 ns/op |      218 ns/op |             17.2 ns/op |
|  10,000,000 | 26804440 ns/op |      432 ns/op |             35.1 ns/op |

**: Since `v0.3.0` weightedrand can efficiently utilize a single Chooser across
multiple CPU cores in parallel, making it even faster in overall throughput. See
[PR#2](https://github.com/mroth/weightedrand/pull/2) for details. Informal
benchmarks conducted on an Intel Xeon W-2140B CPU (8 core @ 3.2GHz,
hyperthreading enabled).*

Don't be mislead by these numbers into thinking `weightedrand` is always the
right choice! If you are only picking from the same distribution once,
`randutil` will be faster. `weightedrand` optimizes for repeated calls at the
expense of some initialization time and memory storage.

## Caveats

Note this library utilizes `math/rand` instead of `crypto/rand`, as it is
optimized for performance, and is not intended to be used for cryptographically
secure requirements.

## Credits

To better understand the algorithm used in this library (as well as the one used
in randutil) check out this great blog post: [Weighted random generation in Python](https://eli.thegreenplace.net/2010/01/22/weighted-random-generation-in-python/).
