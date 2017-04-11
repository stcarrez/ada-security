#!/bin/sh
lcov --base-directory . --directory . -c -o security.cov
bin/security_harness -xml security-aunit.xml
lcov --base-directory . --directory . -c -o security.cov
lcov --remove security.cov "/usr*" -o security.cov
lcov --remove security.cov "regtests*" -o security.cov
lcov --remove security.cov "ada-util/*" -o security.cov
lcov --remove security.cov ada-security/b__security_harness.adb -o security.cov
rm -rf cover
genhtml -o ./cover -t "test coverage" --num-spaces 4 security.cov
 
