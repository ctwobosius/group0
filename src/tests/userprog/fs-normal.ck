# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(fs-normal) begin
(fs-normal) create "test.txt"
(fs-normal) open "test.txt"
(fs-normal) end
fs-normal: exit(0)
EOF
pass;
