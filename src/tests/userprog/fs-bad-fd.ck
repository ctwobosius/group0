# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(fs-bad-fd) begin
fs-bad-fd: exit(-1)
EOF
pass;