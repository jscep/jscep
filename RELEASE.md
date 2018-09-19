# Release Process

## Run Maven Release Process

```bash
git clone git@github.com:jscep/jscep.git
cd jscep
./release.sh
```
## Publish to Maven Central

- Login to https://oss.sonatype.org/
- Open 'Staging Repositories'
- Close Repository
- Release Repository
- Search Nexus for 'jscep'
- Copy Maven dependency fragment

## Publish Release on GitHub

- Go to https://github.com/jscep/jscep/releases
- You should see the release tag from the Maven release process
- Click on the tag
- Click Edit
- Upload `jscep-<version>.jar`, `jscep-<version>-javadoc.jar` and `jscep-<version>-sources.jar`
- Add release notes detailing bugs, PRs, etc
- Add Maven dependency fragment
