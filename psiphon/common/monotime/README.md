Originally forked from https://github.com/Psiphon-Labs/goarista/commit/690920d232c6046c512b4527417e1d9a2b930c92.

With the addition of https://github.com/Psiphon-Labs/goarista/commit/d002785f4c6725d9f62f0e3e7b1e2a20455ed027:

```
Add helpers for Psiphon integration
* monotime.Time type makes it clear when
  a non-"wall" clock time is being used.
* functions including Add, Sub, After, and
  Before enable drop-in replacement of
  time.Now() with monotime.Now() for
  duration calculations.
```
