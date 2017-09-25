# Contributing

## Building/running

For development, you can just `go get` or `go build` the identityserver or use the `docker-compose.yml` file in the root of this repository.

Browse to https://dev.itsyou.online:8443

* dev.itsyou.online is a public DNS entry that points to 127.0.0.1 and ::1
* By default, the self signed development certificate in the `devcert` folder is loaded. If this certificate is not present, a self signed certificate will be generated and the identityserver will be started with that one. This can be forced by specifying the `-ignore-devcert` flag on the commandline.

When building for production usage, a reproducible build and a minimal docker to run it is wanted.

The `publish.sh` script builds the identityserver in a docker and places the statically linked binary in the`dist`.
After this, a minimal docker `itsyouonline:latest` is created that is pushed to docker hub for deployment.

## Changes to the website

In order to make the html files and assets available for the identityserver, you need to regenerate the assets.
This can be done in two modes development mode and production mode,

### Production Mode
Make sure you have go-bindata and go-raml installed:
```
go get -u github.com/jteeuwen/go-bindata/...
go get -u github.com/Jumpscale/go-raml
```

After this execute `go generate` in the root folder of the repository. Commit the overwritten go files in the packaged folder.

### Development mode

To switch to development mode run the script [`builddev.sh`](builddev.sh).

### Bower dependencies

Although 3rd party dependencies are installed through bower,
only the relevant files should be checked in and be in the `thirdpartyassets` folder when packaging using `go generate`.

## Conventions

Submit unit tests for your changes. Go has a great test framework built in; use
it! Take a look at existing tests for inspiration. Run the full test
suite on your branch before
submitting a pull request.

Update the documentation when creating or modifying features. Test your
documentation changes for clarity, concision, and correctness, as well as a
clean documentation build.

Write clean code. Universally formatted code promotes ease of writing, reading,
and maintenance. Always run `gofmt -s -w file.go` on each changed file before
committing your changes. Most editors have plug-ins that do this automatically.

Pull request descriptions should be as clear as possible and include a reference
to all the issues that they address.

Commit messages must start with a capitalized and short summary (max. 50 chars)
written in the imperative, followed by an optional, more detailed explanatory
text which is separated from the summary by an empty line.

Code review comments may be added to your pull request. Discuss, then make the
suggested modifications and push additional commits to your feature branch. Post
a comment after pushing. New commits show up in the pull request automatically,
but the reviewers are notified only when you comment.

Pull requests must be cleanly rebased on top of master without multiple branches
mixed into the PR.

**Git tip**: If your PR no longer merges cleanly, use `rebase master` in your
feature branch to update your pull request rather than `merge master`.

Before you make a pull request, squash your commits into logical units of work
using `git rebase -i` and `git push -f`. A logical unit of work is a consistent
set of patches that should be reviewed together: for example, upgrading the
version of a vendored dependency and taking advantage of its now available new
feature constitute two separate units of work. Implementing a new function and
calling it in another file constitute a single logical unit of work. The very
high majority of submissions should have a single commit, so if in doubt: squash
down to one.

After every commit, make sure the test suite passes. Include documentation
changes in the same pull request so that a revert would remove all traces of
the feature or fix.

Include an issue reference like `Closes #XXXX` or `Fixes #XXXX` in commits that
close an issue. Including references automatically closes the issue on a merge.

Please see the [Coding Style](#coding-style) for further guidelines.


## Limit the number of external libraries

While we are not going to reinvent the wheel all the time, there must be a good reason to add an external library. This software values security very high so all external libraries have to be vendored and checked in to prevent an attack by manipulating external git repositories and slipping in our codebase without us noticing. The less dependencies, the lower the risk and the higher the likelihood of us noticing a suspicious change.


## Coding Style

Unless explicitly stated, we follow all coding guidelines from the Go
community. While some of these standards may seem arbitrary, they somehow seem
to result in a solid, consistent codebase.

It is possible that the code base does not currently comply with these
guidelines. We are not looking for a massive PR that fixes this, since that
goes against the spirit of the guidelines. All new contributions should make a
best effort to clean up and make the code base better than they left it.
Obviously, apply your best judgement. Remember, the goal here is to make the
code base easier for humans to navigate and understand. Always keep that in
mind when nudging others to comply.

The rules:

1. All code should be formatted with `gofmt -s`.
2. All code should pass the default levels of
   [`golint`](https://github.com/golang/lint).
3. All code should follow the guidelines covered in [Effective
   Go](http://golang.org/doc/effective_go.html) and [Go Code Review
   Comments](https://github.com/golang/go/wiki/CodeReviewComments).
4. Comment the code. Tell us the why, the history and the context.
5. Document _all_ declarations and methods, even private ones. Declare
   expectations, caveats and anything else that may be important. If a type
   gets exported, having the comments already there will ensure it's ready.
6. Variable name length should be proportional to it's context and no longer.
   `noCommaALongVariableNameLikeThisIsNotMoreClearWhenASimpleCommentWouldDo`.
   In practice, short methods will have short variable names and globals will
   have longer names.
7. No underscores in package names. If you need a compound name, step back,
   and re-examine why you need a compound name. If you still think you need a
   compound name, lose the underscore.
8. No utils or helpers packages. If a function is not general enough to
   warrant it's own package, it has not been written generally enough to be a
   part of a util package. Just leave it unexported and well-documented.
9. All tests should run with `go test` and outside tooling should not be
   required. No, we don't need another unit testing framework. Assertion
   packages are acceptable if they provide _real_ incremental value.
10. Even though we call these "rules" above, they are actually just
    guidelines. Since you've read all the rules, you now know that.
