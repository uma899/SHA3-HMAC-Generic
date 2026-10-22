Run test vectors file to get vec.txt then run testbench. \
For HMAC, SHA3 modules are needed. Hence make sure to compile them as well.  \
**Padding hardware removed.** Data has to be sent as chunks of 32 bit by processor (hence padding handled by processor). Use padded data for testing also.

Hardware is made as low as possible. Beware of clock cycles. *Try optimising...*
