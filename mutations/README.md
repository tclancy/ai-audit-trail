# Mutations

One unified diff per invariant (`I1.diff`, `I2.diff`, …) that deletes or disables the mechanism. CI applies each in a throwaway checkout and asserts the test suite goes red, and separately asserts each still applies cleanly to HEAD (I15). A mutation that no longer applies is a CI failure, not a cleanup task: it means a refactor disarmed a tripwire.
