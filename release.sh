#!/bin/bash -x
GPG_TTY=$(tty)
export GPG_TTY
mvn clean release:clean && \
mvn release:prepare && \
mvn release:perform
