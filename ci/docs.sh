#!/bin/sh

rm -rf target/doc
mkdir -p target/doc

cp ci/landing-page-head.html target/doc/index.html

for target in x86_64-unknown-freebsd i686-unknown-freebsd; do
	echo documenting $target
	cargo doc --target $target
	echo "<li><a href=\"$target/jail/index.html\">$target</a></li>" >> target/doc/index.html
	cp -a target/$target/doc target/doc/$target
done

ls -l target/

cat ci/landing-page-footer.html >> target/doc/index.html

# If we're on travis, not a PR, and on the right branch, publish!
if [ "$TRAVIS_PULL_REQUEST" = "false" ] && [ "$TRAVIS_BRANCH" = "master" ]; then
	pip install ghp_import --install-option="--prefix=$HOME/.local"
	$HOME/.local/bin/ghp-import -n target/doc
	git push -qf https://${GH_TOKEN}@github.com/${TRAVIS_REPO_SLUG}.git gh-pages
fi
