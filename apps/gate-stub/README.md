# gate-stub (M1)

Minimal reference gate: takes a cart, consults the oracle stub, writes a record via `audittrail.Log`, returns the receipt line. Its own test suite includes the I10 mutation: delete the `record()` call and every request must reject.
