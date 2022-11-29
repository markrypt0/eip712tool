# eip712tool
Tool for creating and validating EIP-712 domain separator and message hashes written in C
Developed for linux build and execution

sim712.c simulates the keepkey driving algorithms for eip712.c. The firmware modules eip712.c and eip712.h should be 100% portable without change to this simulator for testing and validation. The include files in the directories ./src/sim_include may or may not be portable between implementations (confirm_sm.h is not, for example). Add any necessary stubs to sim_stubs.c

obsolete_eip712.c is a standalone tool that was used to develop and validate the keepkey firmware module eip712.c, it is now obsolete and replaced by sim712.c

