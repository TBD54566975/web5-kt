# Conventions

We attempt to follow
the [Library creators' guidelines](https://kotlinlang.org/docs/jvm-api-guidelines-introduction.html).
This ensures that the library is robust.

## Automated Checks

* Style is done via the [.editorconfig](.editorconfig) file.
* We use [detekt](https://detekt.dev/) for static code analysis, as well as formatting and style checks.
  The [config file](./config/detekt.yml)
  contains details of some of the choices we've made.
* [Explicit API mode](https://kotlinlang.org/docs/jvm-api-guidelines-backward-compatibility.html#explicit-api-mode) is
  enabled in order to increase API transparency.
