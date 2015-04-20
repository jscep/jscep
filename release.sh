#!/bin/bash -x
mvn clean release:clean && \
mvn release:prepare && \
mvn release:perform && \
git pull origin master --tags && \
git checkout $(git tag | tail -n1) && \
mvn clean install source:jar javadoc:jar com.googlecode.maven-gcu-plugin:maven-gcu-plugin:1.1:upload && \
git checkout master
