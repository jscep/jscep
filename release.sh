#!/bin/bash -x
mvn clean release:clean && \
mvn release:prepare && \
mvn release:perform
