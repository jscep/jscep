#!/bin/bash -x
GPG_TTY=$(tty)
export GPG_TTY
eval "$(ssh-agent -s)"
ssh-add -K ~/.ssh/id_rsa
mvn clean release:clean && \
mvn release:prepare && \
mvn release:perform
