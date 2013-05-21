mvn clean release:clean
mvn release:prepare
mvn release:perform
read -p "Enter release tag:" tag
git checkout $tag
mvn clean install source:jar javadoc:jar com.googlecode.maven-gcu-plugin:maven-gcu-plugin:1.1:upload
git checkout master
