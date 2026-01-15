
# HashTest
A program for just in time detection of SDCs without needing to pre-generate a
corpus.

NOTE: This is still a work in progress. Information will be added periodically

## Definition of Terms

* **Corpus**: A corpus is a collection of tests and initial states that can be
  executed by the test execution code.

## Versioning
`hashtest[_runner]` is versioned with "major.minor.patch" syntax. The minor
version is
incremented when for the same given seed a "different" [see below for definition
of different] set of corpuses are produced. The patch version will be updated
whenver a notable change occurs that does not affect the contents of the
corpuses.

### Corpus Equivalence for the Purposes of Versioning
Two corpuses (A & B) are considered equivalent iff the following is true

* For every test in Corpus A, there exists exactly 1 test in Corpus B with the
same seed and the test content of each corpus (and vice versa).
    * Two test contents are compared by calculating the hash of both strings.
* For every initial state in Corpus A, there exists exactly 1 initial state in
Corpus B with the same seed and register values (and vice versa).
    * Initial states will be compared by hashing the entropy buffers used to set
      the register values.

### Translation to Versioning
For versioning of HashTest [Runner] the minor version must be bumped if for the
same given seed at command line and configuration provided to the test
generation code, a different set of corpuses are produced. This includes both
tracking the order of execution of the corpuses and the content of the corpuses
themselves.
